"""Prepare only the ignored BetTail lab; never link, start, or migrate a cloud project."""

import json
import os
import secrets
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "var/labs/bettail"
TOOL = ROOT / "var/tools/supabase-2.117.0/supabase.exe"


def local_environment():
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.upper().startswith(("SUPABASE_", "DOCKER_"))
    }
    environment.update(
        SUPABASE_HOME=str(ROOT / "var/supabase-home"),
        SUPABASE_TELEMETRY_DISABLED="1",
        DO_NOT_TRACK="1",
        DOCKER_HOST="npipe:////./pipe/dockerDesktopLinuxEngine",
    )
    return environment


def prepare():
    if not TOOL.is_file():
        raise SystemExit("Install the verified, pinned local CLI first.")
    if not LAB.resolve().is_relative_to(ROOT / "var"):
        raise SystemExit("Lab directory escaped the private workspace.")
    config_dir = LAB / "supabase"
    config_dir.mkdir(parents=True, exist_ok=True)
    key_path = config_dir / "signing_keys.json"
    if not key_path.exists():
        # Generate before configuring signing_keys_path. Capture private output, never print it.
        result = subprocess.run(
            [str(TOOL), "gen", "signing-key", "--algorithm", "ES256", "--workdir", str(LAB)],
            cwd=LAB,
            env=local_environment(),
            capture_output=True,
            timeout=30,
            check=False,
        )
        if result.returncode:
            raise SystemExit("Local signing-key generation failed; no private output was printed.")
        key = json.loads(result.stdout)
        if key.get("kty") != "EC" or key.get("crv") != "P-256" or not key.get("d"):
            raise SystemExit("Unexpected local signing-key format.")
        with key_path.open("x", encoding="utf-8") as handle:
            json.dump([key], handle)
    env_path = LAB / ".env"
    if not env_path.exists():
        values = {
            "SUPABASE_AUTH_JWT_SECRET": secrets.token_urlsafe(48),
            "SUPABASE_AUTH_PUBLISHABLE_KEY": "sb_publishable_" + secrets.token_urlsafe(24),
            "SUPABASE_AUTH_SECRET_KEY": "sb_secret_" + secrets.token_urlsafe(24),
            "SUPABASE_DB_ROOT_KEY": secrets.token_hex(32),
        }
        with env_path.open("x", encoding="utf-8") as handle:
            handle.write("\n".join(f"{name}={value}" for name, value in values.items()) + "\n")
    template = (ROOT / "integrations/supabase/config.toml").read_bytes()
    config = config_dir / "config.toml"
    if config.exists() and config.read_bytes() != template:
        # The initial empty CLI-generated config is retained for audit before replacement.
        backup = config_dir / "initial-config.toml"
        if backup.exists():
            raise SystemExit("Existing lab configuration differs; inspect instead of overwriting.")
        with backup.open("xb") as handle:
            handle.write(config.read_bytes())
    config.write_bytes(template)
    print(
        "Prepared the isolated local lab configuration and fresh private auth keys. No services started."
    )


if __name__ == "__main__":
    prepare()
