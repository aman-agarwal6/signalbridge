import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent
VAR_DIR = BASE_DIR / "var"
VAR_DIR.mkdir(exist_ok=True)
LOCAL = os.environ.get("SB_MODE", "local") == "local"
key_file = VAR_DIR / "django-secret"
# An explicitly supplied key wins; the local key file is created only when none is given,
# so a read-only checkout (for example the isolated Shuffle receiver) can still start.
if LOCAL and not os.environ.get("SB_SECRET_KEY") and not key_file.exists():
    import secrets

    try:
        with key_file.open("x") as handle:
            handle.write(secrets.token_urlsafe(64))
    except FileExistsError:
        pass
SECRET_KEY = os.environ.get("SB_SECRET_KEY") or (key_file.read_text() if LOCAL else "")
if len(SECRET_KEY) < 50:
    raise ImproperlyConfigured("Set a random SB_SECRET_KEY with at least 50 characters.")
DEBUG = False
ALLOWED_HOSTS = (
    ["127.0.0.1", "localhost", "[::1]", "testserver"]
    if LOCAL
    else os.environ.get("SB_ALLOWED_HOSTS", "").split(",")
)
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "bridge",
]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "bridge.federation_middleware.FederatedSessionPolicy",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "bridge.middleware.SecurityHeaders",
]
ROOT_URLCONF = "config.urls"
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "bridge.context.workspace",
            ]
        },
    }
]
WSGI_APPLICATION = "config.wsgi.application"
if os.environ.get("SB_DB_HOST"):
    if LOCAL and (
        os.environ["SB_DB_HOST"] not in ("127.0.0.1", "localhost", "::1", "db")
        or os.environ.get("SB_DB_NAME", "signalbridge") != "signalbridge"
    ):
        raise ImproperlyConfigured(
            "Local mode permits only the named SignalBridge database on loopback or the private Compose db service."
        )
    if LOCAL and any(name.upper().startswith("PG") and value for name, value in os.environ.items()):
        raise ImproperlyConfigured(
            "Local database mode refuses inherited PG settings. Use only the explicit SB_DB configuration."
        )
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "HOST": os.environ["SB_DB_HOST"],
            "PORT": os.environ.get("SB_DB_PORT", "5432"),
            "NAME": os.environ.get("SB_DB_NAME", "signalbridge"),
            "USER": os.environ.get("SB_DB_USER", "signalbridge"),
            "PASSWORD": os.environ["SB_DB_PASSWORD"],
            "CONN_MAX_AGE": 0,
        }
    }
    if LOCAL:
        options = {"sslmode": "disable", "gssencmode": "disable"}
        address = {"127.0.0.1": "127.0.0.1", "localhost": "127.0.0.1", "::1": "::1"}.get(
            os.environ["SB_DB_HOST"]
        )
        if address:
            options["hostaddr"] = address
        DATABASES["default"]["OPTIONS"] = options
elif LOCAL:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": VAR_DIR / "signalbridge.sqlite3",
            "OPTIONS": {"timeout": 20, "transaction_mode": "IMMEDIATE"},
        }
    }
else:
    raise ImproperlyConfigured("PostgreSQL configuration is required outside local mode.")
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
TEST_RUNNER = "bridge.runner.EvidenceRunner"
USE_TZ = True
TIME_ZONE = "UTC"
STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = VAR_DIR / "static"
LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/login/"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Strict"
CSRF_COOKIE_SAMESITE = "Strict"
SESSION_COOKIE_SECURE = not LOCAL
CSRF_COOKIE_SECURE = not LOCAL
SESSION_COOKIE_AGE = 3600
FEDERATED_AUTH_ENABLED = os.environ.get("SB_OIDC_ENABLED", "0") == "1"
MONITORED_WORKERS = os.environ.get("SB_MONITORED_WORKERS", "default").split(",")
SOC_SEGMENTED_EXPORT = os.environ.get("SB_SOC_SEGMENTED_EXPORT", "0") == "1"
SECURE_SSL_REDIRECT = not LOCAL
SECURE_HSTS_SECONDS = 31536000 if not LOCAL else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = not LOCAL
SECURE_HSTS_PRELOAD = not LOCAL
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"
DATA_UPLOAD_MAX_MEMORY_SIZE = 16384
FILE_UPLOAD_MAX_MEMORY_SIZE = 16384
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 14},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
]
if LOCAL and (VAR_DIR / "lab-keys.json").exists():
    import json

    for app, key in json.loads((VAR_DIR / "lab-keys.json").read_text()).items():
        if app in ("bettail", "netted") and isinstance(key, str) and len(key) >= 32:
            os.environ.setdefault("SB_" + app.upper() + "_LAB_KEY", key)
if LOCAL and (VAR_DIR / "synthetic-keys.json").exists():
    import json

    for app, key in json.loads((VAR_DIR / "synthetic-keys.json").read_text()).items():
        if app in ("bettail", "netted") and isinstance(key, str) and len(key) >= 32:
            os.environ.setdefault("SB_" + app.upper() + "_SYNTH_KEY", key)
