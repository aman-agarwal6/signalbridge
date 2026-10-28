"""Read Windows Security XML and Entra ID JSON exports into flat rows for the Sigma rules.

Windows: <Event> records as Splunk's XmlWinEventLog stores them. A row holds EventID, Computer,
Channel and the event time, plus every EventData field under its own name. These are the field
names SigmaHQ's Windows rules use.

Entra ID: one Azure Monitor diagnostic record per line, the format diagnostic settings and Event
Hubs deliver. A row holds:
- Microsoft Sentinel's SigninLogs and AuditLogs column names (ENTRA_COLUMNS), taken from the
  record;
- the record's own dotted paths, such as properties.status.errorCode, except where a path differs
  from a Sentinel column only by letter case (the column wins);
- each audit change under its display name, such as ConsentContext.IsAdminConsent, with the new
  value. Sentinel keeps these inside TargetResources; SigmaHQ rules sometimes name them directly.

Every row is tagged with the Sigma log source it belongs to. Records of other kinds
(non-interactive and service principal sign-ins, risk events) are counted and set aside.

LANL host events (the false-alarm baseline, see baseline.py): one JSON record per line, with
attribute names LANL standardized and values it de-identified. lanl_row gives each attribute its
Windows EventData name (LANL_FIELDS). Source becomes Workstation on NTLM checks (4776), as Windows
names it there, and IpAddress on the other events.
"""

import json
import re
from collections import Counter
from datetime import datetime, timedelta
from xml.etree import ElementTree

WINDOWS_SECURITY = "windows/security"
ENTRA_SIGNIN = "azure/signinlogs"
ENTRA_AUDIT = "azure/auditlogs"
LOG_SOURCES = (WINDOWS_SECURITY, ENTRA_SIGNIN, ENTRA_AUDIT)
ENTRA_CATEGORIES = {"SignInLogs": ENTRA_SIGNIN, "AuditLogs": ENTRA_AUDIT}

# Sentinel column -> paths in the Azure Monitor record, first present value wins.
ENTRA_COLUMNS = {
    "Category": ("properties.category", "category"),
    "OperationName": ("operationName",),
    "ResultType": ("resultType",),
    "ResultDescription": ("resultDescription",),
    "Result": ("properties.result",),
    "ResultReason": ("properties.resultReason",),
    "LoggedByService": ("properties.loggedByService",),
    "ActivityDisplayName": ("properties.activityDisplayName",),
    "UserPrincipalName": ("properties.userPrincipalName",),
    "IPAddress": ("properties.ipAddress", "callerIpAddress"),
    "AppDisplayName": ("properties.appDisplayName",),
    "AuthenticationProtocol": ("properties.authenticationProtocol",),
    "AuthenticationRequirement": ("properties.authenticationRequirement",),
    "Status": ("properties.status",),
    "InitiatedBy": ("properties.initiatedBy",),
    "TargetResources": ("properties.targetResources",),
    "AdditionalDetails": ("properties.additionalDetails",),
}

# LANL host-log attribute -> Windows EventData name. LANL renamed TargetUserName to UserName.
LANL_FIELDS = {
    "Computer": "Computer",
    "LogHost": "Computer",
    "UserName": "TargetUserName",
    "DomainName": "TargetDomainName",
    "ServiceName": "ServiceName",
    "Status": "Status",
    "FailureReason": "FailureReason",
    "LogonType": "LogonType",
    "AuthenticationPackage": "AuthenticationPackage",
}
# LANL gives seconds from the start of collection, not dates; rows count them from this time.
LANL_START = datetime(1970, 1, 1)

EVENT = re.compile(r"<Event[\s>].*?</Event>", re.DOTALL)
ISO_TIME = re.compile(r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.(\d+))?(?:Z|\+00:00)?")


def timestamp(value):
    """ISO 8601 UTC time -> 'YYYY-MM-DD HH:MM:SS.mmm', the form SQLite's julianday() reads."""
    match = ISO_TIME.fullmatch(value or "")
    if not match:
        raise ValueError(f"unexpected timestamp: {value!r}")
    day, clock, fraction = match.groups()
    return f"{day} {clock}.{(fraction or '').ljust(3, '0')[:3]}"


def text_value(value):
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def children(element, name):
    """Child elements by local name. Exports carry more than one event namespace (2004, 2006)."""
    if element is None:
        return []
    return [item for item in element if item.tag.rpartition("}")[2] == name]


def child(element, name):
    return next(iter(children(element, name)), None)


def child_text(element, name):
    found = child(element, name)
    return found.text if found is not None else None


def windows_rows(text):
    """Yield (log source, row) for each Security-channel event."""
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        raise ValueError("XML with a document type or entity declaration is refused")
    for match in EVENT.finditer(text):
        event = ElementTree.fromstring(match.group(0))
        system = child(event, "System")
        created = child(system, "TimeCreated")
        row = {
            "timestamp": timestamp(created.get("SystemTime") if created is not None else None),
            "EventID": child_text(system, "EventID"),
            "Computer": child_text(system, "Computer"),
            "Channel": child_text(system, "Channel"),
        }
        for data in children(child(event, "EventData"), "Data"):
            name = data.get("Name")
            if name and name.lower() not in {key.lower() for key in row}:
                row[name] = (data.text or "").strip()
        if row["Channel"] == "Security":
            yield WINDOWS_SECURITY, row


def dotted_paths(value, prefix=""):
    """Scalar leaves of nested objects under dotted names; lists stay whole, as JSON."""
    if isinstance(value, dict):
        for key, inner in value.items():
            yield from dotted_paths(inner, f"{prefix}{key}.")
    else:
        yield prefix[:-1], text_value(value)


def path_value(record, path):
    value = record
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def modified_properties(record):
    for target in path_value(record, "properties.targetResources") or []:
        for change in target.get("modifiedProperties") or []:
            name, value = change.get("displayName"), change.get("newValue")
            if not name:
                continue
            try:
                decoded = json.loads(value) if isinstance(value, str) else value
            except ValueError:
                decoded = value
            yield name, decoded if isinstance(decoded, str) else text_value(value)


def entra_row(record):
    row = {"timestamp": timestamp(record.get("time"))}
    for column, paths in ENTRA_COLUMNS.items():
        values = (path_value(record, path) for path in paths)
        row[column] = text_value(next((v for v in values if v is not None), None))
    taken = {key.lower() for key in row}
    for name, value in [*dotted_paths(record), *modified_properties(record)]:
        if name.lower() not in taken:
            row[name] = value
            taken.add(name.lower())
    return row


def entra_rows(text, ignored):
    """Yield (log source, row) for interactive sign-ins and audit records; count the rest."""
    for line in text.splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        source = ENTRA_CATEGORIES.get(record.get("category"))
        if source is None:
            ignored[str(record.get("category"))] += 1
            continue
        yield source, entra_row(record)


def lanl_row(record):
    """One LANL host event as a Windows Security row."""
    seconds = record.get("Time")
    if not isinstance(seconds, int) or isinstance(seconds, bool) or seconds < 0:
        raise ValueError(f"unexpected LANL time: {seconds!r}")
    event_id = text_value(record.get("EventID"))
    row = {
        "timestamp": (LANL_START + timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S.000"),
        "EventID": event_id,
    }
    for name, column in LANL_FIELDS.items():
        if record.get(name) is not None and column not in row:
            row[column] = text_value(record[name])
    if record.get("Source") is not None:
        row["Workstation" if event_id == "4776" else "IpAddress"] = text_value(record["Source"])
    return row


def read_rows(path, log_format):
    """Rows by log source, plus a count of the records set aside by category."""
    text = path.read_text(encoding="utf-8-sig")
    rows, ignored = {source: [] for source in LOG_SOURCES}, Counter()
    if log_format == "windows_xml":
        records = windows_rows(text)
    elif log_format == "entra_json":
        records = entra_rows(text, ignored)
    else:
        raise ValueError(f"unknown log format: {log_format}")
    for source, row in records:
        rows[source].append(row)
    return rows, dict(sorted(ignored.items()))
