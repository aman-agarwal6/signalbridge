import os
from importlib import import_module

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
application = get_wsgi_application()

# Capture source identities before serving requests. Native and container entry
# points both use this application; editing rules requires a process restart.
for module in ("bridge.detection_catalog", "bridge.evaluation"):
    import_module(module)
