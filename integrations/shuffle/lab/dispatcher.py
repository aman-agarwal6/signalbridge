"""Authenticated dispatcher for the isolated Shuffle lab; never a deployment tool.

Runs inside the pinned HTTP app image on the lab's private network. It creates
one fixed Shuffle workflow (a single HTTP POST action), then drives each
scenario as a genuine Shuffle execution against SignalBridge's signed review
API and records Shuffle's own execution IDs with the receiver's answers.
Secrets come from the environment and never enter output.
"""

import ast
import hashlib
import hmac
import json
import os
import socket
import sys
import threading
import time
import uuid
from datetime import datetime, timezone

import requests

SHUFFLE = os.environ.get("SHUFFLE_URL", "http://shuffle-backend:5001")
RECEIVER = "http://signalbridge:8000"
SELF = "http://dispatcher"
TIMEOUT_PORT, LOST_PORT = 9009, 9010
WORKFLOW_NAME = "SignalBridge synthetic analyst review handoff"
EXECUTION_SECONDS = 90


class LabError(RuntimeError):
    """Closed codes only."""


def require(condition, code):
    if not condition:
        raise LabError(code)


def shuffle(method, path, payload=None):
    response = requests.request(
        method,
        SHUFFLE + path,
        headers={"Authorization": "Bearer " + os.environ["SHUFFLE_APIKEY"]},
        json=payload,
        timeout=20,
    )
    require(response.status_code < 300, "shuffle_api_" + path.split("/")[3])
    return response.json()


def signed(key_id, secret_env, method, path, body=b""):
    nonce, at = str(uuid.uuid4()), datetime.now(timezone.utc).isoformat()
    value = "\n".join(
        ("SB-SERVICE/1", key_id, nonce, at, method, path, hashlib.sha256(body).hexdigest())
    )
    signature = hmac.new(
        os.environ[secret_env].encode(), value.encode(), hashlib.sha256
    ).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-SB-Service-Key": key_id,
        "X-SB-Service-Nonce": nonce,
        "X-SB-Service-Time": at,
        "X-SB-Service-Signature": signature,
    }


def shuffle_body(text):
    """The body Shuffle's HTTP app 1.4.0 actually sends: json.dumps(ast.literal_eval(body))."""
    return json.dumps(ast.literal_eval(text)) if text.strip().startswith("{") else text


def task_request(case_id, case_version, evidence, idempotency_key, base=RECEIVER, headers=None):
    path = f"/api/v1/cases/{case_id}/review-task/"
    # Shuffle's HTTP app re-serializes JSON bodies with default separators, so sign the
    # form it will send; signing compact JSON made every request fail authentication.
    text = json.dumps(
        {
            "case_version": case_version,
            "evidence_sha256": evidence,
            "idempotency_key": idempotency_key,
            "task_kind": "review_case_evidence",
        },
        sort_keys=True,
    )
    require(shuffle_body(text) == text, "body_not_shuffle_stable")
    body = text.encode()
    headers = headers or signed("shuffle-task", "SB_SERVICE_SHUFFLE_TASK", "POST", path, body)
    return {
        "url": base + path,
        "headers": "\n".join(f"{k}: {v}" for k, v in headers.items()),
        "body": body.decode(),
        "timeout": "3",
    }, headers


def create_workflow():
    created = shuffle("POST", "/api/v1/workflows", {"name": WORKFLOW_NAME, "description": "lab"})
    apps = [a for a in shuffle("GET", "/api/v1/apps") if a["name"] == "http"]
    require(len(apps) == 1 and apps[0]["app_version"] == "1.4.0", "http_app_inventory")
    app = apps[0]
    template = next(a for a in app["actions"] if a["name"] == "POST")
    action_id = str(uuid.uuid4())
    parameters = []
    for parameter in template["parameters"]:
        parameter = dict(parameter)
        parameter["value"] = "$exec." + parameter["name"]
        parameters.append(parameter)
    action = {
        **template,
        "id": action_id,
        "app_name": "http",
        "app_version": "1.4.0",
        "app_id": app["id"],
        "label": "post_review_task",
        "environment": "Shuffle",
        "parameters": parameters,
        "position": {"x": 0, "y": 0},
        "is_valid": True,
        "errors": [],
    }
    workflow = {
        **created,
        "actions": [action],
        "triggers": [],
        "branches": [],
        "start": action_id,
        "is_valid": True,
        "errors": [],
    }
    saved = shuffle("PUT", "/api/v1/workflows/" + created["id"], workflow)
    require(saved.get("success", True) is not False, "workflow_save")
    return created["id"], action_id


def execute(workflow_id, action_id, argument):
    started = shuffle(
        "POST",
        f"/api/v1/workflows/{workflow_id}/execute",
        {"execution_argument": json.dumps(argument), "start": action_id},
    )
    execution_id = started.get("execution_id")
    require(isinstance(execution_id, str) and len(execution_id) == 36, "execution_id")
    deadline = time.monotonic() + EXECUTION_SECONDS
    while time.monotonic() < deadline:
        state = shuffle(
            "POST",
            "/api/v1/streams/results",
            {"execution_id": execution_id, "authorization": started["authorization"]},
        )
        if state.get("status") in ("FINISHED", "ABORTED", "FAILURE"):
            results = state.get("results") or []
            action = results[0] if results else {}
            try:
                reply = json.loads(action.get("result", ""))
            except (TypeError, ValueError):
                reply = {}
            body = reply.get("body") if isinstance(reply, dict) else None
            return {
                "execution_id": execution_id,
                "execution_status": state["status"],
                "action_status": action.get("status"),
                "http_status": reply.get("status") if isinstance(reply, dict) else None,
                "body": body if isinstance(body, dict) else {},
            }
        time.sleep(1)
    raise LabError("execution_deadline")


def blackhole():
    """Accepts and holds connections without replying: a receiver timeout."""
    server = socket.create_server(("0.0.0.0", TIMEOUT_PORT))
    held = []
    while True:
        connection, _ = server.accept()
        held.append(connection)


def lost_reply():
    """Forwards one request to the receiver, then drops its reply: a lost reply."""
    server = socket.create_server(("0.0.0.0", LOST_PORT))
    while True:
        connection, _ = server.accept()
        with connection:
            connection.settimeout(5)
            data = b""
            while b"\r\n\r\n" not in data:
                data += connection.recv(65536)
            head, _, body = data.partition(b"\r\n\r\n")
            length = next(
                (
                    int(line.split(b":", 1)[1])
                    for line in head.split(b"\r\n")
                    if line.lower().startswith(b"content-length:")
                ),
                0,
            )
            while len(body) < length:
                body += connection.recv(65536)
            lines = head.split(b"\r\n")
            method, path = lines[0].split(b" ")[:2]
            headers = {}
            for line in lines[1:]:
                name, _, value = line.partition(b":")
                if name.lower().startswith(b"x-sb-") or name.lower() == b"content-type":
                    headers[name.decode()] = value.strip().decode()
            requests.request(
                method.decode(), RECEIVER + path.decode(), headers=headers, data=body, timeout=10
            )
            # The receiver committed; the caller never learns the outcome.


def main():
    for target in (blackhole, lost_reply):
        threading.Thread(target=target, daemon=True).start()
    seed = json.loads(open(sys.argv[1], encoding="utf8").read())["cases"]
    docs, expenses = seed["documents"], seed["expenses"]
    workflow_id, action_id = create_workflow()
    rows = {}

    def run(name, argument):
        rows[name] = execute(workflow_id, action_id, argument)
        return rows[name]

    # Resolve current evidence first through the separate read-only key.
    path = f"/api/v1/cases/{docs['case_id']}/evidence/"
    evidence = requests.get(
        RECEIVER + path,
        headers=signed("shuffle-read", "SB_SERVICE_SHUFFLE_READ", "GET", path),
        timeout=10,
    )
    require(evidence.status_code == 200, "evidence_read")
    current = evidence.json()
    require(current["evidence_sha256"] == docs["evidence_sha256"], "evidence_binding")
    first_key = str(uuid.uuid4())
    argument, _ = task_request(
        docs["case_id"], current["case_version"], current["evidence_sha256"], first_key
    )
    first = run("first", argument)
    retry, retry_headers = task_request(
        docs["case_id"], current["case_version"], current["evidence_sha256"], first_key
    )
    run("retry_new_nonce", retry)
    replay, _ = task_request(
        docs["case_id"],
        current["case_version"],
        current["evidence_sha256"],
        first_key,
        headers=retry_headers,
    )
    run("replayed_request", replay)
    changed, _ = task_request(docs["case_id"], 7, current["evidence_sha256"], first_key)
    run("changed_content", changed)
    foreign, _ = task_request(
        expenses["case_id"],
        expenses["case_version"],
        expenses["evidence_sha256"],
        str(uuid.uuid4()),
    )
    run("wrong_scope", foreign)
    stale, _ = task_request(
        docs["case_id"], current["case_version"], current["evidence_sha256"], str(uuid.uuid4())
    )
    run("stale_evidence", stale)
    hung, _ = task_request(
        docs["case_id"],
        current["case_version"] + 1,
        current["evidence_sha256"],
        str(uuid.uuid4()),
        base=f"{SELF}:{TIMEOUT_PORT}",
    )
    run("receiver_timeout", hung)
    lost_key = str(uuid.uuid4())
    lost, _ = task_request(
        docs["case_id"],
        current["case_version"] + 1,
        current["evidence_sha256"],
        lost_key,
        base=f"{SELF}:{LOST_PORT}",
    )
    run("lost_reply", lost)
    recovered, _ = task_request(
        docs["case_id"], current["case_version"] + 1, current["evidence_sha256"], lost_key
    )
    run("retry_after_lost_reply", recovered)
    summary = {
        "workflow_id": workflow_id,
        "first_task_id": first["body"].get("task_id"),
        "scenarios": {
            name: {
                "execution_id": row["execution_id"],
                "execution_status": row["execution_status"],
                "http_status": row["http_status"],
                "duplicate": row["body"].get("duplicate"),
                "task_id": row["body"].get("task_id"),
                "error": row["body"].get("error"),
            }
            for name, row in rows.items()
        },
    }
    sys.stdout.write(json.dumps(summary, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
