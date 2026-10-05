"""Closed Linux header source profile; no host credentials, ports or trust changes."""

from integrations.enterprise.reference_native_settings import *  # noqa: F403
from integrations.zap_enterprise.capture import PROFILE

if os.environ.get("SB_HEADER_PROOF") != "1" or component != "source":  # noqa: F405
    raise ImproperlyConfigured("The fixed native header source profile is not enabled.")  # noqa: F405

REFERENCE_HEADER_PROFILE = PROFILE
MIDDLEWARE = ["reference_lab.header_probe.HeaderProbe", *MIDDLEWARE]  # noqa: F405
