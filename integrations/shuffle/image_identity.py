"""Bounded Docker 29 containerd image identity checks, without I/O or execution.

The caller supplies a reviewed immutable reference and a bounded content reader.
Only metadata blobs are read; layer bytes, signatures and vulnerabilities are
not verified. This profile intentionally rejects unsupported OCI artifacts.
"""

import hashlib
import json
import math
import re

MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_IMAGE_BYTES = 4 * 1024**3
# Preserve the reviewed acquisition's pins. This is not a compatible-runtime claim.
REVIEWED_IMAGES = {
    "backend": "ghcr.io/shuffle/shuffle-backend@sha256:0cc1775e48b7d94b7f16d0be713aa274ced52be24ad521beaaf58c67023fd2e5",
    "worker": "ghcr.io/shuffle/shuffle-worker@sha256:9541c1fef2bc8511727610b565adbd0f7c817c53afee2dd9fef6aad8a971ffb1",
    "orborus": "ghcr.io/shuffle/shuffle-orborus@sha256:3519810b3ca4fe568acefdf15ce6f2deba0ae6f0ff6b84412354d59d663dff31",
    "http": "docker.io/frikky/shuffle@sha256:4c5b6a0b44890ddc227a3ded9fee09f216dddd268ee0acc33e31dfa95fa724fb",
    "opensearch": "opensearchproject/opensearch@sha256:68a688de28fb9bb66601552650b91a52a9fd5e7eac5481dd2b225ecb66fd09b0",
}
REVIEWED_CONFIGS = {
    "http": "sha256:b7f4230658dd394486f4b137eee3759d4728d42cfe9cb6a569d20bc84505c303",
    "opensearch": "sha256:9c4d3b54042a402a11618658d5309121a349aeb60b375deba29334d033e65fc0",
}
INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
MANIFEST_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
CONFIG_TYPES = {
    "application/vnd.oci.image.config.v1+json",
    "application/vnd.docker.container.image.v1+json",
}
LAYER_TYPES = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar+zstd",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
}


class ImageIdentityError(ValueError):
    """A fixed code; never registry, configuration or command content."""


def require(condition, code):
    if not condition:
        raise ImageIdentityError(code)


def digest(value):
    require(
        type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None,
        "content_digest",
    )
    return value


def reference(value):
    require(type(value) is str and len(value) <= 300, "image_reference")
    repository, separator, pin = value.partition("@")
    require(
        separator == "@"
        and re.fullmatch(
            r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+", repository
        )
        is not None,
        "image_reference",
    )
    digest(pin)
    return repository.removeprefix("docker.io/") + "@" + pin


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate_content_key")
        result[key] = value
    return result


def content_json(raw, expected):
    digest(expected)
    require(type(raw) is bytes and 0 < len(raw) <= MAX_METADATA_BYTES, "content_size")
    require("sha256:" + hashlib.sha256(raw).hexdigest() == expected, "content_hash")
    try:
        data = json.loads(raw.decode("utf8"), object_pairs_hook=pairs)
    except (UnicodeError, ValueError, RecursionError) as error:
        if isinstance(error, ImageIdentityError):
            raise
        raise ImageIdentityError("content_json") from None
    require(type(data) is dict, "content_object")
    stack = [(data, 0)]
    count = 0
    while stack:
        item, depth = stack.pop()
        count += 1
        require(depth <= 16 and count <= 20000, "content_complexity")
        require(not isinstance(item, float) or math.isfinite(item), "nonfinite_content")
        if isinstance(item, dict):
            stack.extend((value, depth + 1) for value in item.values())
        elif isinstance(item, list):
            stack.extend((value, depth + 1) for value in item)
    return data


def descriptor(value, media_types, maximum):
    require(type(value) is dict, "descriptor_shape")
    require(type(value.get("mediaType")) is str, "descriptor_type")
    require(value["mediaType"] in media_types, "descriptor_type")
    digest(value.get("digest"))
    require(type(value.get("size")) is int and 0 < value["size"] <= maximum, "descriptor_size")
    # Content is addressed locally; no embedded alternate payload or destination.
    require(not ({"urls", "data", "artifactType"} & value.keys()), "descriptor_alternate")
    return value


def verify_identity(reference_pin, info, read_content, expected_config=None):
    """Verify a manifest/index -> selected manifest -> config chain.

    Docker 29 containerd inspect must run without --platform: Id then identifies
    the pinned target. The selected metadata and runtime must be linux/amd64.
    read_content must bound its own I/O; at most three validated digests are read.
    No returned field includes image configuration, environment or annotations.
    """
    normalized = reference(reference_pin)
    pin = normalized.partition("@")[2]
    if expected_config is not None:
        digest(expected_config)
    require(type(info) is dict and callable(read_content), "inspection_shape")
    require(info.get("Id") == pin, "image_target_id")
    require(
        info.get("Os") == "linux"
        and info.get("Architecture") == "amd64"
        and info.get("Variant", "") == "",
        "image_platform",
    )
    require(type(info.get("Size")) is int and 0 < info["Size"] <= MAX_IMAGE_BYTES, "image_size")
    repos = info.get("RepoDigests")
    require(type(repos) is list and 1 <= len(repos) <= 3, "repo_digests")
    require({reference(value) for value in repos} == {normalized}, "image_repository_pin")

    retained = {}

    def read(pin, expected_size=None):
        digest(pin)
        require(pin not in retained and len(retained) < 3, "content_chain")
        try:
            raw = read_content(pin)
        except Exception:
            raise ImageIdentityError("content_unavailable") from None
        document = content_json(raw, pin)
        if expected_size is not None:
            require(len(raw) == expected_size, "content_descriptor_size")
        retained[pin] = len(raw)
        return document

    document = read(pin)
    target_type = document.get("mediaType")
    require(type(target_type) is str and target_type in INDEX_TYPES | MANIFEST_TYPES, "target_type")
    require(
        type(document.get("schemaVersion")) is int and document["schemaVersion"] == 2,
        "manifest_schema",
    )
    if info.get("Descriptor") is not None:
        target = descriptor(info["Descriptor"], INDEX_TYPES | MANIFEST_TYPES, MAX_METADATA_BYTES)
        require(
            target["digest"] == pin
            and target["size"] == retained[pin]
            and target["mediaType"] == target_type,
            "runtime_descriptor",
        )
    manifest_digest = pin
    if target_type in INDEX_TYPES:
        children = document.get("manifests")
        require(type(children) is list and 1 <= len(children) <= 20, "index_children")
        matches = []
        for row in children:
            descriptor(row, MANIFEST_TYPES, MAX_METADATA_BYTES)
            platform = row.get("platform")
            require(type(platform) is dict, "index_platform")
            require(
                type(platform.get("os")) is str and type(platform.get("architecture")) is str,
                "index_platform",
            )
            if platform["os"] == "linux" and platform["architecture"] == "amd64":
                require(platform.get("variant", "") == "", "index_variant")
                matches.append(row)
        require(len(matches) == 1, "platform_ambiguous")
        selected = matches[0]
        manifest_digest = selected["digest"]
        document = read(manifest_digest, selected["size"])
        require(document.get("mediaType") == selected["mediaType"], "manifest_descriptor_type")
    require(
        type(document.get("schemaVersion")) is int
        and document["schemaVersion"] == 2
        and type(document.get("mediaType")) is str
        and document["mediaType"] in MANIFEST_TYPES,
        "manifest_type",
    )
    config_descriptor = descriptor(document.get("config"), CONFIG_TYPES, MAX_METADATA_BYTES)
    config_digest = config_descriptor["digest"]
    require(expected_config is None or config_digest == expected_config, "reviewed_config_mismatch")
    layers = document.get("layers")
    require(type(layers) is list and 1 <= len(layers) <= 128, "manifest_layers")
    layer_bytes = 0
    for layer in layers:
        descriptor(layer, LAYER_TYPES, MAX_IMAGE_BYTES)
        layer_bytes += layer["size"]
    require(layer_bytes <= MAX_IMAGE_BYTES, "layer_size_total")
    config = read(config_digest, config_descriptor["size"])
    require(
        config.get("os") == "linux"
        and config.get("architecture") == "amd64"
        and config.get("variant", "") == "",
        "config_platform",
    )
    rootfs = config.get("rootfs")
    require(type(rootfs) is dict and rootfs.get("type") == "layers", "config_rootfs")
    diff_ids = rootfs.get("diff_ids")
    require(type(diff_ids) is list and len(diff_ids) == len(layers), "config_layers")
    for value in diff_ids:
        digest(value)
    require(info.get("RootFS") == {"Type": "layers", "Layers": diff_ids}, "runtime_rootfs_mismatch")
    return {
        "target_digest": pin,
        "manifest_digest": manifest_digest,
        "config_digest": config_digest,
        "metadata_bytes": sum(retained.values()),
        "layer_count": len(layers),
        "declared_layer_bytes": layer_bytes,
        "layer_bytes_verified": False,
    }


def existing_components(raw_ids):
    """Plan validation of a partial download inventory; never delete or trust it.

    Input is `docker image ls --all --quiet --no-trunc` from the dedicated guest.
    Every returned component still needs verify_component before reuse. Unknown
    or dangling image IDs require inspection, not cleanup or silent acceptance.
    """
    require(type(raw_ids) is bytes and len(raw_ids) <= 4096, "inventory_size")
    try:
        lines = raw_ids.decode("ascii").splitlines()
    except UnicodeError:
        raise ImageIdentityError("inventory_encoding") from None
    require(len(lines) <= 20, "inventory_count")
    for line in lines:
        digest(line)
    known = {value.partition("@")[2] for value in REVIEWED_IMAGES.values()}
    require(set(lines) <= known, "unreviewed_image")
    return [name for name, value in REVIEWED_IMAGES.items() if value.partition("@")[2] in lines]


def verify_component(name, info, read_content):
    """Apply the fixed acquisition pins and component-specific reported-size cap."""
    require(type(name) is str and name in REVIEWED_IMAGES, "unreviewed_component")
    result = verify_identity(REVIEWED_IMAGES[name], info, read_content, REVIEWED_CONFIGS.get(name))
    require(info["Size"] <= (4 if name == "opensearch" else 2) * 1024**3, "component_size")
    return result
