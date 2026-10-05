"""Modeled ZAP API observations and socket doubles; no native scanner proof."""

import copy
import hashlib
import json
import time
from contextlib import nullcontext
from unittest.mock import Mock, patch
from urllib.parse import parse_qs

from django.test import SimpleTestCase

from integrations.enterprise.reference_http import ORIGIN
from integrations.zap_enterprise.capture import HeaderProfileError, render_har
from integrations.zap_enterprise.passive import (
    ALERT_FIELDS,
    ANCESTORS,
    GET_ROUTES,
    MAX_CALLS,
    Client,
    analyze_phase,
    configure,
    validate_alerts,
    validate_history,
    wait_passive,
)
from tests.test_zap_enterprise_capture import START, rows


def history(phase="fault"):
    result = []
    for row in rows(phase):
        result.append(
            {
                "id": str(row["ordinal"] + 1),
                "type": "15",
                "timestamp": "1790942400000",
                "rtt": "0",
                "cookieParams": "",
                "note": "",
                "requestHeader": f"GET {ORIGIN}{row['path']} HTTP/1.1\r\nHost: 127.0.0.1:18842\r\nContent-Type: application/json\r\n\r\n",
                "requestBody": "",
                "responseHeader": f"{row['http_version']} {row['http_status']} Synthetic\r\n"
                + "".join(f"{k}: {v}\r\n" for k, v in row["headers"].items())
                + "\r\n",
                "responseBody": row["body"],
                "tags": ["JSON"],
            }
        )
    return {"messages": result}


def tree_node(identifier, path):
    """A SiteMap ancestor exactly as the pinned ZAP serializes it (observed natively)."""
    return {
        **history()["messages"][0],
        "id": str(identifier),
        "type": "0",
        "timestamp": "0",
        "requestHeader": f"GET {ORIGIN}{path} HTTP/1.1\r\nHost: 127.0.0.1:18842\r\n\r\n",
        "responseHeader": "HTTP/1.0 0\r\n\r\n",
        "responseBody": "",
        "tags": [],
    }


def alerts():
    value = {name: "" for name in ALERT_FIELDS}
    value.update(
        id="0",
        pluginId="10021",
        alertRef="10021",
        risk="Low",
        confidence="Medium",
        cweid="693",
        method="GET",
        url=ORIGIN + rows()[1]["path"],
        messageId="2",
        param="x-content-type-options",
        sourceMessageId=None,
        tags={},
    )
    return {"alerts": [value]}


class ModeledAPI:
    def __init__(self, phase="fault"):
        self.phase, self.calls, self.deadline = phase, 0, time.monotonic() + 120
        self.mutations = {}
        self.reads = {
            ("core", "view", "version"): {"version": "2.17.0"},
            ("core", "view", "mode"): {"mode": "safe"},
            ("core", "view", "urls"): {"urls": []},
            ("core", "view", "numberOfMessages"): {"numberOfMessages": "0"},
            ("alert", "view", "numberOfAlerts"): {"numberOfAlerts": "0"},
            ("pscan", "view", "scanOnlyInScope"): {"scanOnlyInScope": "true"},
            ("pscan", "view", "scanners"): {
                "scanners": [
                    {"id": "10021", "enabled": "true"},
                    {"id": "other", "enabled": "false"},
                ]
            },
            ("pscan", "view", "recordsToScan"): {"recordsToScan": "0"},
            ("pscan", "view", "currentTasks"): {"currentTasks": []},
        }

    def api(self, *route, **parameters):
        assert route in GET_ROUTES and parameters == GET_ROUTES[route]
        self.calls += 1
        if route == ("context", "action", "newContext"):
            return {"contextId": "1"}
        if route[1] == "action":
            self.mutations[route] = parameters
            return {"Result": "OK"}
        return copy.deepcopy(self.reads[route])

    def import_capture(self, observations, phase, captured_at):
        assert phase == self.phase
        self.calls += 1
        raw = render_har(observations, phase, captured_at)
        self.reads[("core", "view", "messages")] = history(phase)
        self.reads[("core", "view", "numberOfMessages")] = {"numberOfMessages": "5"}
        self.reads[("alert", "view", "alerts")] = alerts() if phase == "fault" else {"alerts": []}
        self.reads[("alert", "view", "numberOfAlerts")] = {
            "numberOfAlerts": "1" if phase == "fault" else "0"
        }
        return hashlib.sha256(raw).hexdigest()


class EnterprisePassiveTests(SimpleTestCase):
    def test_modeled_finding_and_equivalent_retest_are_explicitly_unattested(self):
        for phase in ("fault", "corrected"):
            client = ModeledAPI(phase)
            with patch("integrations.zap_enterprise.passive.time.sleep"):
                result = analyze_phase(
                    client, rows(phase), phase, START.replace(minute=1).isoformat()
                )
            self.assertTrue(result["api_observations_validated"])
            self.assertFalse(result["runtime_attested"])
            self.assertFalse(result["source_capture_attested"])
            self.assertEqual(len(result["findings"]), 1 if phase == "fault" else 0)
            self.assertEqual(result["history"]["imported_messages"], 5)
            self.assertEqual(result["passive_rule_scope"], ["10021"])
            self.assertEqual(
                client.mutations[("pscan", "action", "enableScanners")], {"ids": "10021"}
            )

    def test_fresh_session_safe_mode_and_expected_version_are_mandatory(self):
        for route, value in (
            (("core", "view", "version"), {"version": "different"}),
            (("core", "view", "mode"), {"mode": "attack"}),
            (("core", "view", "urls"), {"urls": ["https://example.com/"]}),
            (("core", "view", "numberOfMessages"), {"numberOfMessages": "1"}),
            (("alert", "view", "numberOfAlerts"), {"numberOfAlerts": "1"}),
            (("pscan", "view", "scanners"), {"scanners": [{"id": "10021", "enabled": "false"}]}),
            (
                ("pscan", "view", "scanners"),
                {"scanners": [{"id": "10021", "enabled": "true"}, {"id": "1", "enabled": "true"}]},
            ),
        ):
            client = ModeledAPI()
            client.reads[route] = value
            with self.subTest(route=route), self.assertRaises(HeaderProfileError):
                configure(client)

    def test_unfiltered_history_binds_both_same_path_reads_to_distinct_source_events(self):
        result = validate_history(history(), rows(), "fault", "5")
        self.assertNotEqual(result["message_ids"][1], result["message_ids"][4])
        self.assertEqual(result["physical_history_records"], 5)
        self.assertNotEqual(rows()[1]["event_id"], rows()[4]["event_id"])

    def test_internal_tree_record_is_allowed_only_when_empty_and_in_fixed_ancestry(self):
        payload = history()
        payload["messages"].append(tree_node(6, sorted(ANCESTORS)[1]))
        self.assertEqual(validate_history(payload, rows(), "fault", "6")["empty_tree_records"], 1)
        entity = payload["messages"][-1]["requestHeader"].replace(
            "\r\n\r\n", "\r\nContent-Type: application/json\r\n\r\n"
        )
        for key, value in (
            ("responseBody", "nonempty"),
            ("type", "1"),
            ("timestamp", "1"),
            ("tags", ["JSON"]),
            ("requestHeader", entity),
        ):
            altered = copy.deepcopy(payload)
            altered["messages"][-1][key] = value
            with self.subTest(key=key), self.assertRaises(HeaderProfileError):
                validate_history(altered, rows(), "fault", "6")

    def test_native_inventory_with_site_root_and_every_ancestor_is_accepted(self):
        # The pinned image returned 5 imported records plus 9 SiteMap nodes,
        # including the origin itself serialized without a path.
        self.assertIn("", ANCESTORS)
        self.assertEqual(len(ANCESTORS), 9)
        payload = history()
        for offset, path in enumerate(sorted(ANCESTORS)):
            payload["messages"].append(tree_node(6 + offset, path))
        result = validate_history(payload, rows(), "fault", "14")
        self.assertEqual(result["physical_history_records"], 14)
        self.assertEqual(result["empty_tree_records"], 9)
        repeated = copy.deepcopy(payload)
        repeated["messages"].append(tree_node(15, ""))
        with self.assertRaises(HeaderProfileError):
            validate_history(repeated, rows(), "fault", "15")
        untagged = copy.deepcopy(payload)
        untagged["messages"][0]["tags"] = []
        with self.assertRaises(HeaderProfileError):
            validate_history(untagged, rows(), "fault", "14")

    def test_history_wrong_identity_status_scope_body_headers_or_count_fails(self):
        for key, value in (
            ("id", "1"),
            ("responseBody", "different"),
            ("requestBody", "unexpected"),
            ("type", "1"),
            ("responseHeader", "HTTP/1.1 503 Unavailable\r\n\r\n"),
            ("requestHeader", "GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        ):
            payload = history()
            payload["messages"][1][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_history(payload, rows(), "fault", "5")
        with self.assertRaises(HeaderProfileError):
            validate_history(history(), rows(), "fault", "4")

    def test_request_credentials_and_extra_tool_requests_cannot_be_filtered_away(self):
        payload = history()
        payload["messages"][0]["requestHeader"] = payload["messages"][0]["requestHeader"].replace(
            "\r\n\r\n", "\r\nCookie: must-not-be-here\r\n\r\n"
        )
        with self.assertRaises(HeaderProfileError):
            validate_history(payload, rows(), "fault", "5")
        extra = history()
        extra["messages"].append({**extra["messages"][0], "id": "9"})
        with self.assertRaises(HeaderProfileError):
            validate_history(extra, rows(), "fault", "6")

    def test_alert_requires_exact_plugin_history_binding_scope_and_unchanged_controls(self):
        bindings = validate_history(history(), rows(), "fault", "5")["message_ids"]
        self.assertEqual(
            validate_alerts(alerts(), rows(), bindings, "fault", "1")[0]["source_event_id"],
            rows()[1]["event_id"],
        )
        for key, value in (
            ("messageId", "5"),
            ("method", "POST"),
            ("pluginId", "1"),
            ("risk", "High"),
            ("confidence", "Low"),
            ("url", "https://example.com/"),
            ("param", "unrelated"),
        ):
            payload = alerts()
            payload["alerts"][0][key] = value
            with self.subTest(key=key), self.assertRaises(HeaderProfileError):
                validate_alerts(payload, rows(), bindings, "fault", "1")
        with self.assertRaises(HeaderProfileError):
            validate_alerts({"alerts": []}, rows(), bindings, "fault", "0")
        with self.assertRaises(HeaderProfileError):
            validate_alerts(alerts(), rows("corrected"), bindings, "corrected", "1")

    def test_passive_queue_needs_two_empty_samples_and_respects_timeout(self):
        client = ModeledAPI()
        with patch("integrations.zap_enterprise.passive.time.sleep") as sleep:
            wait_passive(client)
        self.assertEqual(client.calls, 4)
        sleep.assert_called_once_with(0.25)
        client.deadline = time.monotonic() - 1
        with self.assertRaises(HeaderProfileError):
            wait_passive(client)

    def test_closed_api_refuses_active_actions_changed_limits_and_any_target_request(self):
        client = Client("a" * 64, time.monotonic() + 120)
        with patch("integrations.zap_enterprise.passive.http.client.HTTPConnection") as socket:
            for route, parameters in (
                (("ascan", "action", "scan"), {}),
                (("spider", "action", "scan"), {}),
                (("core", "view", "messages"), {"start": "0", "count": "0"}),
                (("core", "action", "setMode"), {"mode": "attack"}),
            ):
                with self.subTest(route=route), self.assertRaises(HeaderProfileError):
                    client.api(*route, **parameters)
            with self.assertRaises(HeaderProfileError):
                client.request("GET", ORIGIN + rows()[1]["path"])
        socket.assert_not_called()

    def test_har_post_has_no_credentials_or_data_in_api_url_and_disables_resend(self):
        client = Client("a" * 64, time.monotonic() + 120)
        connection = Mock()
        connection.getresponse.return_value.status = 200
        connection.getresponse.return_value.getheader.return_value = None
        connection.getresponse.return_value.read.return_value = b'{"Result":"OK"}'
        with (
            patch(
                "integrations.zap_enterprise.passive.http.client.HTTPConnection",
                return_value=connection,
            ),
            patch(
                "integrations.zap_enterprise.passive.network_deadline",
                side_effect=lambda _: nullcontext(),
            ),
        ):
            client.import_capture(rows(), "fault", START.replace(minute=1).isoformat())
        call = connection.request.call_args
        self.assertEqual(call.args, ("POST", "/JSON/exim/action/importHar/"))
        body = parse_qs(call.kwargs["body"].decode())
        self.assertEqual(set(body), {"data", "sendRequests", "maxMessages"})
        self.assertEqual(body["sendRequests"], ["false"])
        self.assertEqual(body["maxMessages"], ["5"])
        self.assertEqual(len(json.loads(body["data"][0])["log"]["entries"]), 5)
        self.assertNotIn(client.key, call.args[1])
        connection.close.assert_called_once()

    def test_api_redirect_error_oversize_or_exhausted_budget_never_yields_validated_observations(
        self,
    ):
        for status, location, raw in (
            (302, None, b"{}"),
            (200, "https://example.com/", b"{}"),
            (200, None, b'{"code":"bad"}'),
            (200, None, b"x" * (2 * 1024 * 1024 + 1)),
        ):
            client = Client("a" * 64, time.monotonic() + 120)
            connection = Mock()
            connection.getresponse.return_value.status = status
            connection.getresponse.return_value.getheader.return_value = location
            connection.getresponse.return_value.read.return_value = raw
            with (
                self.subTest(status=status),
                patch(
                    "integrations.zap_enterprise.passive.http.client.HTTPConnection",
                    return_value=connection,
                ),
                patch(
                    "integrations.zap_enterprise.passive.network_deadline",
                    side_effect=lambda _: nullcontext(),
                ),
                self.assertRaises(HeaderProfileError),
            ):
                client.api("core", "view", "version")
            connection.close.assert_called_once()
        client.calls = MAX_CALLS
        with (
            patch("integrations.zap_enterprise.passive.http.client.HTTPConnection") as socket,
            self.assertRaises(HeaderProfileError),
        ):
            client.api("core", "view", "version")
        socket.assert_not_called()
