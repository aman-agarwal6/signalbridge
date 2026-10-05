"""Private TLS/provisioning generation, called only by a separately approved run.

Cryptography imports are lazy. No import, offline profile check or test creates
credentials, changes host trust, contacts a service or installs a dependency.
"""

import argparse
import ipaddress
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .native_profile import HERE, dashboard, require


def write(path, raw):
    raw = raw.encode("utf8") if isinstance(raw, str) else raw
    require(type(raw) is bytes and 0 < len(raw) <= 262144 and not path.exists())
    with path.open("xb") as stream:
        stream.write(raw)


def configuration():
    """Public configurations; credentials remain file references."""
    return {
        "prometheus": {
            "global": {
                "scrape_interval": "15s",
                "scrape_timeout": "7s",
                "evaluation_interval": "15s",
            },
            "rule_files": ["/config/signalbridge-alerts.yml"],
            "scrape_configs": [
                {
                    "job_name": "signalbridge",
                    "scheme": "https",
                    "metrics_path": "/metrics/",
                    "static_configs": [{"targets": ["127.0.0.1:18843"]}],
                    "authorization": {
                        "type": "Bearer",
                        "credentials_file": "/run/secrets/metrics-token",
                    },
                    "tls_config": {
                        "ca_file": "/run/secrets/ca.pem",
                        "min_version": "TLS12",
                        "insecure_skip_verify": False,
                    },
                    "follow_redirects": False,
                    "proxy_from_environment": False,
                    "enable_http2": False,
                    "sample_limit": 256,
                    "label_limit": 8,
                    "label_name_length_limit": 64,
                    "label_value_length_limit": 128,
                    "body_size_limit": "64KB",
                }
            ],
        },
        "web": {
            "tls_server_config": {
                "cert_file": "/run/secrets/server.pem",
                "key_file": "/run/secrets/server-key.pem",
                "client_ca_file": "/run/secrets/ca.pem",
                "client_auth_type": "RequireAndVerifyClientCert",
                "min_version": "TLS12",
                "client_allowed_sans": [
                    "urn:signalbridge:monitoring:verifier",
                    "urn:signalbridge:monitoring:grafana",
                ],
            },
            "http_server_config": {"http2": False},
        },
    }


def grafana_ini():
    return """[paths]
data = /var/lib/grafana
logs = /tmp
plugins = /var/lib/grafana/plugins
provisioning = /config/provisioning
[server]
protocol = https
min_tls_version = TLS1.2
http_addr = 127.0.0.1
http_port = 13000
domain = 127.0.0.1
root_url = https://127.0.0.1:13000/
cert_file = /run/secrets/server.pem
cert_key = /run/secrets/server-key.pem
read_timeout = 5s
router_logging = false
[security]
admin_user = sb-monitoring-verifier
admin_password = $__file{/run/secrets/admin-password}
secret_key = $__file{/run/secrets/grafana-secret}
cookie_secure = true
cookie_samesite = strict
allow_embedding = false
disable_gravatar = true
[users]
allow_sign_up = false
allow_org_create = false
[auth.anonymous]
enabled = false
[auth.basic]
enabled = true
[analytics]
enabled = false
reporting_enabled = false
check_for_updates = false
check_for_plugin_updates = false
[plugins]
preinstall_disabled = true
preinstall_auto_update = false
plugin_admin_enabled = false
public_key_retrieval_disabled = true
[smtp]
enabled = false
[unified_alerting]
enabled = false
[dataproxy]
timeout = 5
tls_handshake_timeout_seconds = 5
response_limit = 1048576
[log]
mode = console
level = error
"""


def generate(directory):
    """Authority signing key exists only in memory; issue distinct server/client keys."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    directory = Path(directory)
    require(directory.is_dir())
    now, expiry = datetime.now(timezone.utc), datetime.now(timezone.utc) + timedelta(minutes=30)
    authority = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Disposable monitoring authority")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(authority.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(seconds=30))
        .not_valid_after(expiry)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(authority.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(authority.public_key()),
            critical=False,
        )
        .sign(authority, hashes.SHA256())
    )
    ca_pem = ca.public_bytes(serialization.Encoding.PEM)

    def issue(label, client=False):
        key = ec.generate_private_key(ec.SECP256R1())
        san = (
            x509.UniformResourceIdentifier("urn:signalbridge:monitoring:" + label)
            if client
            else x509.IPAddress(ipaddress.ip_address("127.0.0.1"))
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)]))
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(seconds=30))
            .not_valid_after(expiry)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(True, False, False, False, False, False, False, False, False),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]
                ),
                critical=False,
            )
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(authority.public_key()),
                critical=False,
            )
            .sign(authority, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM), key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    verifier, graf_client = issue("verifier", True), issue("grafana", True)
    metrics, password = secrets.token_urlsafe(48), secrets.token_urlsafe(48)
    for role in ("runner", "prometheus", "grafana"):
        secret_dir = directory / role / "secrets"
        secret_dir.mkdir(parents=True, exist_ok=False)
        certificate, key = issue(role)
        write(secret_dir / "ca.pem", ca_pem)
        write(secret_dir / "server.pem", certificate)
        write(secret_dir / "server-key.pem", key)
        if role in ("runner", "prometheus"):
            write(secret_dir / "metrics-token", metrics)
        if role == "runner":
            write(secret_dir / "client.pem", verifier[0])
            write(secret_dir / "client-key.pem", verifier[1])
            write(secret_dir / "ingest-secret", secrets.token_urlsafe(48))
            write(secret_dir / "django-secret", secrets.token_urlsafe(48))
            write(secret_dir / "admin-password", password)
        if role == "grafana":
            write(secret_dir / "admin-password", password)
            write(secret_dir / "grafana-secret", secrets.token_urlsafe(48))
    for role in ("prometheus", "grafana"):
        (directory / role / "config").mkdir()
    public = configuration()
    prom = directory / "prometheus/config"
    write(prom / "prometheus.yml", json.dumps(public["prometheus"], indent=2) + "\n")
    write(prom / "web.yml", json.dumps(public["web"], indent=2) + "\n")
    write(prom / "signalbridge-alerts.yml", (HERE / "signalbridge-alerts.yml").read_bytes())
    graf = directory / "grafana/config"
    write(graf / "grafana.ini", grafana_ini())
    (graf / "provisioning/datasources").mkdir(parents=True)
    (graf / "provisioning/dashboards").mkdir()
    # This inline private provisioning is mounted only into Grafana, never published.
    datasource = {
        "apiVersion": 1,
        "datasources": [
            {
                "name": "SignalBridge protected exporter",
                "uid": "signalbridge-prometheus",
                "type": "prometheus",
                "access": "proxy",
                "url": "https://127.0.0.1:19090",
                "isDefault": True,
                "editable": False,
                "jsonData": {
                    "tlsAuth": True,
                    "tlsAuthWithCACert": True,
                    "tlsSkipVerify": False,
                    "serverName": "127.0.0.1",
                    "timeInterval": "15s",
                    "httpMethod": "POST",
                },
                "secureJsonData": {
                    "tlsCACert": ca_pem.decode("ascii"),
                    "tlsClientCert": graf_client[0].decode("ascii"),
                    "tlsClientKey": graf_client[1].decode("ascii"),
                },
            }
        ],
    }
    write(
        graf / "provisioning/datasources/signalbridge.yml", json.dumps(datasource, indent=2) + "\n"
    )
    write(
        graf / "provisioning/dashboards/signalbridge.yml",
        json.dumps(
            {
                "apiVersion": 1,
                "providers": [
                    {
                        "name": "SignalBridge",
                        "orgId": 1,
                        "type": "file",
                        "disableDeletion": True,
                        "allowUiUpdates": False,
                        "updateIntervalSeconds": 30,
                        "options": {"path": "/config/dashboard"},
                    }
                ],
            }
        )
        + "\n",
    )
    (graf / "dashboard").mkdir()
    content = dashboard()
    content["description"] = (
        "Standalone synthetic SQLite operational proof; no native reference-run monitoring or 24-hour SLA claim."
    )
    content["panels"][0]["options"]["content"] += (
        "\n\nThis finite profile observes fresh synthetic intake and real worker processing in disposable SQLite. Filesystem headroom is the application tmpfs; the host capacity guard is separate. Query verification does not establish browser rendering."
    )
    write(graf / "dashboard/signalbridge.json", json.dumps(content, indent=2) + "\n")
    write(
        directory / "certificate-validity.json",
        json.dumps(
            {
                "created_at": now.isoformat(),
                "expires_at": expiry.isoformat(),
                "signing_key_persisted": False,
                "host_trust_changed": False,
            }
        )
        + "\n",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory")
    generate(Path(parser.parse_args().directory))


if __name__ == "__main__":
    main()
