"""Fixed identity destinations, usable before Django or any provider starts."""

PROVIDER_ORIGIN = "https://127.0.0.2:18844"
ISSUER = PROVIDER_ORIGIN + "/realms/signalbridge"
CLIENT_ID = "signalbridge-console"
CALLBACK = "https://127.0.0.1:18842/sso/callback/"
AUTHORIZATION = ISSUER + "/protocol/openid-connect/auth"
TOKEN = ISSUER + "/protocol/openid-connect/token"
