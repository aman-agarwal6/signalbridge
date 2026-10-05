"""Closed Windows permission diagnostics; never retain native error text."""

from bridge.contract import ContractError, parse_json

from .verification import LabControlError

KIND = "signalbridge-private-acl-failure"
MODES = ("SecureEmpty", "Verify")
FIELDS = {"kind", "mode", "phase", "checked_count"}
_ABSENT = object()


def _valid_hresult(value):
    return value is None or type(value) is int and -(2**31) <= value <= 2**31 - 1


class PrivateACLFailure(LabControlError):
    """A failed helper check, carrying only validated, fixed branch metadata."""

    def __init__(self, mode, phase, checked_count, *, api_hresult=_ABSENT):
        if (
            type(mode) is not str
            or mode not in MODES
            or type(phase) is not int
            or not 1 <= phase <= 17
            or type(checked_count) is not int
            or not 0 <= checked_count <= 2501
            or api_hresult is not _ABSENT
            and (phase != 8 or not _valid_hresult(api_hresult))
        ):
            raise LabControlError("Invalid private ACL diagnostic.")
        super().__init__("The private ACL helper rejected its fixed permission check.")
        self._branch = (mode, phase, checked_count)
        if api_hresult is not _ABSENT:
            self._api_hresult = api_hresult

    def metadata(self, expected_mode):
        # Revalidate before serialization; never copy arbitrary exception attrs.
        branch = getattr(self, "_branch", None)
        if type(branch) is not tuple or len(branch) != 3:
            return None
        mode, phase, checked = branch
        if (
            type(mode) is not str
            or mode not in MODES
            or mode != expected_mode
            or type(phase) is not int
            or not 1 <= phase <= 17
            or type(checked) is not int
            or not 0 <= checked <= 2501
        ):
            return None
        value = {"kind": KIND, "mode": mode, "phase": phase, "checked_count": checked}
        api_hresult = getattr(self, "_api_hresult", _ABSENT)
        if api_hresult is not _ABSENT:
            if phase != 8 or not _valid_hresult(api_hresult):
                return None
            value["api_hresult"] = api_hresult
        return value


def failure(raw, expected_mode):
    """Accept only one bounded helper JSON document, with the requested mode."""
    if (
        type(raw) is not bytes
        or not 0 < len(raw) <= 1024
        or type(expected_mode) is not str
        or expected_mode not in MODES
    ):
        return None
    try:
        value = parse_json(raw)
        if (
            type(value) is not dict
            or set(value) not in (FIELDS, FIELDS | {"api_hresult"})
            or value["kind"] != KIND
            or value["mode"] != expected_mode
        ):
            return None
        numeric = {"api_hresult": value["api_hresult"]} if "api_hresult" in value else {}
        return PrivateACLFailure(value["mode"], value["phase"], value["checked_count"], **numeric)
    except (ContractError, LabControlError):
        return None
