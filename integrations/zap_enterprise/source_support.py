"""Finite native source header operations, with predicate-only operator output."""

import json
import os
import sys

from integrations.enterprise import reference_native_support as base


def configure():
    if (
        os.environ.get("SB_HEADER_PROOF") != "1"
        or os.environ.get("SB_SOURCE_COMPONENT") != "source"
    ):
        raise ValueError("The native header source opt-in is required.")
    value = base.configure()
    os.environ["DJANGO_SETTINGS_MODULE"] = "integrations.zap_enterprise.source_settings"
    return value


def header_evidence():
    from django.contrib.auth import get_user_model

    from reference_lab.header_probe import require_profile
    from reference_lab.models import BoundedHeaderFault
    from reference_lab.seed import DOCUMENT_ID

    require_profile()
    member = get_user_model().objects.get(username="document_member")
    rows = list(BoundedHeaderFault.objects.all()[:2])
    if len(rows) != 1 or rows[0].resource_id != DOCUMENT_ID or rows[0].user_id != member.pk:
        raise ValueError("The header fault inventory changed.")
    fault = rows[0]
    if fault.enabled or not 0 < (fault.expires_at - fault.started_at).total_seconds() <= 600:
        raise ValueError("The bounded header fault is not safely withdrawn.")
    return {
        **base.source_evidence(),
        "header_fault": {
            "enabled": False,
            "scope": "fixed synthetic document/member header only",
            "started_at": fault.started_at.isoformat(),
            "expires_at": fault.expires_at.isoformat(),
        },
    }


def operate(action):
    if action not in ("header-on", "header-off", "inspect-header"):
        raise ValueError("Operator action escaped the fixed header scope.")
    configure()
    import django
    from django.db import connection

    django.setup()
    base.verify_database_identity(connection, "source")
    if action == "inspect-header":
        return header_evidence()
    from reference_lab.header_probe import set_header_fault

    enabled = action == "header-on"
    set_header_fault(enabled, 300)
    return {"enabled": enabled, "maximum_seconds": 300}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("One fixed header operation is required.")
    try:
        print(json.dumps(operate(sys.argv[1]), sort_keys=True))
    except Exception as error:
        print(json.dumps({"completed": False, "error_class": type(error).__name__}))
        raise SystemExit(1) from None
