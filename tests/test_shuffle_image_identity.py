"""Synthetic metadata only: no daemon, network, image execution or guest boot."""

import copy
import hashlib
import json
from unittest import TestCase
from unittest.mock import patch

from integrations.shuffle import image_identity as identity


def encode(value):
    return json.dumps(value, separators=(",", ":")).encode()


def hashed(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def fixture(
    *, indexed=False, docker=False, config_change=None, manifest_change=None, index_change=None
):
    content = {}

    def add(value):
        raw = encode(value)
        pin = hashed(raw)
        content[pin] = raw
        return {"digest": pin, "size": len(raw)}

    config = {
        "os": "linux",
        "architecture": "amd64",
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "1" * 64]},
    }
    if config_change:
        config_change(config)
    cfg = {
        "mediaType": "application/vnd.docker.container.image.v1+json"
        if docker
        else "application/vnd.oci.image.config.v1+json",
        **add(config),
    }
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json"
        if docker
        else "application/vnd.oci.image.manifest.v1+json",
        "config": cfg,
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip"
                if docker
                else "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": "sha256:" + "2" * 64,
                "size": 128,
            }
        ],
    }
    if manifest_change:
        manifest_change(manifest)
    desc = {"mediaType": manifest["mediaType"], **add(manifest)}
    selected = desc["digest"]
    if indexed:
        index = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json"
            if docker
            else "application/vnd.oci.image.index.v1+json",
            "manifests": [{**desc, "platform": {"os": "linux", "architecture": "amd64"}}],
        }
        if index_change:
            index_change(index)
        desc = {"mediaType": index["mediaType"], **add(index)}
    pin = desc["digest"]
    ref = "docker.io/example/fixture@" + pin
    info = {
        "Id": pin,
        "Os": "linux",
        "Architecture": "amd64",
        "RepoDigests": ["example/fixture@" + pin],
        "RootFS": {"Type": "layers", "Layers": ["sha256:" + "1" * 64]},
        "Size": 4096,
        "Descriptor": desc,
    }
    return ref, info, content, cfg["digest"], selected


class ShuffleImageIdentityTests(TestCase):
    def checked(self, data):
        ref, info, content, cfg, _ = data
        return identity.verify_identity(ref, info, content.__getitem__, cfg)

    def test_docker_and_oci_manifests_and_indexes(self):
        for indexed in (False, True):
            for docker in (False, True):
                with self.subTest(indexed=indexed, docker=docker):
                    data = fixture(indexed=indexed, docker=docker)
                    result = self.checked(data)
                    self.assertEqual(result["manifest_digest"], data[4])
                    self.assertEqual(result["config_digest"], data[3])
                    self.assertEqual(result["target_digest"], data[1]["Id"])
                    self.assertEqual(result["layer_count"], 1)
                    self.assertEqual(result["declared_layer_bytes"], 128)
                    self.assertFalse(result["layer_bytes_verified"])

    def test_target_id_is_not_config_id(self):
        data = fixture()
        data[1]["Id"] = data[3]
        with self.assertRaisesRegex(identity.ImageIdentityError, "image_target_id"):
            self.checked(data)

    def test_bounded_metadata_reads_do_not_read_layers_or_uris(self):
        ref, info, content, cfg, _ = fixture(indexed=True)
        seen = []

        def read(pin):
            seen.append(pin)
            return content[pin]

        result = identity.verify_identity(ref, info, read, cfg)
        self.assertEqual(len(seen), 3)
        self.assertEqual(set(seen), set(content))
        self.assertEqual(result["metadata_bytes"], sum(map(len, content.values())))

    def test_repository_and_reference_are_bound(self):
        data = fixture()
        pin = data[1]["Id"]
        for repo in (
            "foreign.example/fixture@" + pin,
            "other/fixture@" + pin,
            "../fixture@" + pin,
            12,
            "example/fixture:latest",
        ):
            with self.subTest(repo=repo), self.assertRaises(identity.ImageIdentityError):
                info = {**data[1], "RepoDigests": [repo]}
                identity.verify_identity(data[0], info, data[2].__getitem__, data[3])
        data[1]["RepoDigests"].append(data[0])
        self.checked(data)

    def test_tampered_metadata_bytes_rejected_at_each_link(self):
        data = fixture(indexed=True)
        for pin in data[2]:
            with (
                self.subTest(pin=pin),
                self.assertRaisesRegex(identity.ImageIdentityError, "content_hash"),
            ):
                changed = dict(data[2])
                changed[pin] += b" "
                identity.verify_identity(data[0], data[1], changed.__getitem__, data[3])

    def test_reviewed_config_pin_is_separate_and_required_when_supplied(self):
        data = fixture()
        with self.assertRaisesRegex(identity.ImageIdentityError, "reviewed_config_mismatch"):
            identity.verify_identity(data[0], data[1], data[2].__getitem__, "sha256:" + "3" * 64)

    def test_descriptor_sizes_and_types_are_checked(self):
        mutations = (
            {"manifest_change": lambda m: m["config"].update(size=True)},
            {"manifest_change": lambda m: m["config"].update(size=1)},
            {"manifest_change": lambda m: m["config"].update(mediaType="untrusted")},
            {"indexed": True, "index_change": lambda m: m["manifests"][0].update(size=1)},
            {
                "indexed": True,
                "index_change": lambda m: m["manifests"][0].update(
                    mediaType="application/vnd.docker.distribution.manifest.v2+json"
                ),
            },
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(identity.ImageIdentityError):
                self.checked(fixture(**mutation))

    def test_runtime_descriptor_must_match_retained_target(self):
        for field, value in (
            ("size", 1),
            ("digest", "sha256:" + "3" * 64),
            ("mediaType", "application/vnd.oci.image.index.v1+json"),
        ):
            data = fixture()
            data[1]["Descriptor"][field] = value
            with self.subTest(field=field), self.assertRaises(identity.ImageIdentityError):
                self.checked(data)
        data = fixture()
        del data[1]["Descriptor"]  # Older API shape omits this optional field.
        self.checked(data)

    def test_platform_ambiguity_and_malformed_index_fail_closed(self):
        changes = (
            lambda m: m.update(manifests=[]),
            lambda m: m.update(manifests=m["manifests"] * 2),
            lambda m: m["manifests"][0].update(platform=[]),
            lambda m: m["manifests"][0]["platform"].update(architecture="arm64"),
            lambda m: m["manifests"][0]["platform"].update(variant="v3"),
            lambda m: m.update(manifests=[None]),
            lambda m: m.update(schemaVersion=2.0),
        )
        for change in changes:
            with self.subTest(change=change), self.assertRaises(identity.ImageIdentityError):
                self.checked(fixture(indexed=True, index_change=change))

    def test_selected_metadata_and_runtime_platform_must_agree(self):
        for field, value in (("Os", "windows"), ("Architecture", "arm64"), ("Variant", "v3")):
            data = fixture()
            data[1][field] = value
            with self.subTest(field=field), self.assertRaises(identity.ImageIdentityError):
                self.checked(data)
        for change in (
            lambda c: c.update(os="windows"),
            lambda c: c.update(architecture="arm64"),
            lambda c: c.update(variant="v3"),
        ):
            with self.assertRaisesRegex(identity.ImageIdentityError, "config_platform"):
                self.checked(fixture(config_change=change))

    def test_layers_and_runtime_rootfs_must_agree(self):
        for change in (
            lambda m: m.update(layers=[]),
            lambda m: m.update(layers=m["layers"] * 2),
            lambda m: m["layers"][0].update(size=-1),
            lambda m: m["layers"][0].update(digest="invalid"),
        ):
            with self.assertRaises(identity.ImageIdentityError):
                self.checked(fixture(manifest_change=change))
        data = fixture()
        data[1]["RootFS"]["Layers"] = ["sha256:" + "3" * 64]
        with self.assertRaisesRegex(identity.ImageIdentityError, "runtime_rootfs_mismatch"):
            self.checked(data)

    def test_external_or_embedded_descriptors_are_rejected(self):
        for field, value in (
            ("urls", ["https://untrusted.invalid/private"]),
            ("data", "private-sentinel"),
        ):
            with self.assertRaisesRegex(identity.ImageIdentityError, "descriptor_alternate"):
                self.checked(
                    fixture(
                        manifest_change=lambda m, field=field, value=value: m["config"].update(
                            {field: value}
                        )
                    )
                )

    def test_invalid_inspection_and_image_size_rejected(self):
        data = fixture()
        for info in (
            None,
            [],
            {**data[1], "Size": True},
            {**data[1], "Size": identity.MAX_IMAGE_BYTES + 1},
            {**data[1], "RepoDigests": []},
        ):
            with self.assertRaises(identity.ImageIdentityError):
                identity.verify_identity(data[0], info, data[2].__getitem__, data[3])

    def test_malformed_duplicate_nonfinite_or_nonobject_json_rejected(self):
        for raw in (
            b"{",
            b"[]",
            b"\xff",
            b'{"a":1,"a":2}',
            b'{"a":NaN}',
            b'{"a":1e999}',
            b'{"a":-Infinity}',
        ):
            with self.subTest(raw=raw), self.assertRaises(identity.ImageIdentityError):
                identity.content_json(raw, hashed(raw))

    def test_content_size_depth_and_item_limits(self):
        nested = {}
        for _ in range(18):
            nested = {"child": nested}
        for raw in (
            b"",
            b" " * (identity.MAX_METADATA_BYTES + 1),
            encode(nested),
            encode({"items": list(range(20001))}),
        ):
            with self.assertRaises(identity.ImageIdentityError):
                identity.content_json(raw, hashed(raw))

    def test_content_reader_failures_do_not_leak_private_data(self):
        data = fixture()

        def failed(_):
            raise OSError("private-sentinel")

        with self.assertRaisesRegex(identity.ImageIdentityError, "content_unavailable") as error:
            identity.verify_identity(data[0], data[1], failed, data[3])
        self.assertNotIn("private-sentinel", str(error.exception))
        self.assertTrue(error.exception.__suppress_context__)
        for raw in (None, "private-sentinel", [], b"private-sentinel"):
            with self.assertRaises(identity.ImageIdentityError):
                identity.verify_identity(data[0], data[1], lambda _, raw=raw: raw, data[3])

    def test_private_config_and_annotations_not_returned(self):
        data = fixture(config_change=lambda c: c.update(config={"Env": ["private-sentinel"]}))
        result = self.checked(data)
        self.assertNotIn("private-sentinel", json.dumps(result))
        changed = copy.deepcopy(data[1])
        changed["Config"] = {"Env": ["private-sentinel"]}
        self.assertEqual(
            identity.verify_identity(data[0], changed, data[2].__getitem__, data[3]), result
        )

    def test_partial_inventory_is_preserved_as_unverified_candidates(self):
        self.assertEqual(identity.existing_components(b""), [])
        pins = [value.partition("@")[2] for value in identity.REVIEWED_IMAGES.values()]
        self.assertEqual(
            identity.existing_components(("\n".join(pins[:4]) + "\n").encode()),
            ["backend", "worker", "orborus", "http"],
        )
        self.assertEqual(
            identity.existing_components(("\n".join(pins + pins) + "\n").encode()),
            list(identity.REVIEWED_IMAGES),
        )

    def test_unknown_dangling_or_malformed_inventory_is_not_reusable(self):
        for raw in (b"sha256:" + b"a" * 64, b"short-id", b"\xff", b"\n", b"a" * 4097):
            with self.assertRaises(identity.ImageIdentityError):
                identity.existing_components(raw)

    def test_component_wrapper_enforces_fixed_pins_and_size(self):
        data = fixture()
        with self.assertRaises(identity.ImageIdentityError):
            identity.verify_component("foreign", data[1], data[2].__getitem__)
        with self.assertRaisesRegex(identity.ImageIdentityError, "image_target_id"):
            identity.verify_component("http", data[1], data[2].__getitem__)
        with (
            patch.dict(identity.REVIEWED_IMAGES, {"http": data[0]}),
            patch.dict(identity.REVIEWED_CONFIGS, {"http": data[3]}),
        ):
            self.assertEqual(
                identity.verify_component("http", data[1], data[2].__getitem__),
                self.checked(data),
            )
            data[1]["Size"] = 2 * 1024**3 + 1
            with self.assertRaisesRegex(identity.ImageIdentityError, "component_size"):
                identity.verify_component("http", data[1], data[2].__getitem__)
