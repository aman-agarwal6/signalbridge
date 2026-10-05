"""Optional Authlib Django client; imports do not install packages or open sockets."""

import logging
import re

from django.views.decorators.debug import sensitive_variables

from .configuration import AUTHORIZATION, TOKEN
from .protocol import TokenRejected, verify_login_token
from .transport import IdentityTransportError, token_post


@sensitive_variables()
def create_client(configuration):
    # Import only after the opt-in profile and request boundary have been checked.
    from authlib.integrations.django_client import DjangoIntegration, DjangoOAuth2App
    from requests import Response
    from requests.adapters import BaseAdapter

    # Authlib's DEBUG statements include token/PKCE data. Keep its records out of
    # application/root handlers even when a local operator enables root DEBUG.
    logger = logging.getLogger("authlib")
    logger.handlers = [logging.NullHandler()]
    logger.propagate = False

    class ShortStateIntegration(DjangoIntegration):
        expires_in = 300

    class FixedTokenAdapter(BaseAdapter):
        @sensitive_variables()
        def send(self, request, **kwargs):
            if request.method != "POST" or request.url != TOKEN:
                raise IdentityTransportError()
            response = Response()
            response.status_code = 200
            response.url = TOKEN
            response.request = request
            response.headers["Content-Type"] = "application/json"
            response._content = token_post(request.body, ca_file=configuration.ca_file)
            response._content_consumed = True
            return response

        def close(self):
            pass

    class StrictDjangoClient(DjangoOAuth2App):
        @sensitive_variables()
        def authorize_access_token(self, request, **kwargs):
            data = self.framework.get_state_data(request.session, request.POST.get("state"))
            if (
                not isinstance(data, dict)
                or data.get("redirect_uri") != configuration.callback
                or not isinstance(data.get("code_verifier"), str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", data["code_verifier"])
                or not isinstance(data.get("nonce"), str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{43}", data["nonce"])
            ):
                raise TokenRejected()
            return super().authorize_access_token(request, **kwargs)

        def _get_oauth_client(self, **metadata):
            session = super()._get_oauth_client(**metadata)
            session.trust_env = False
            session.mount("https://", FixedTokenAdapter())
            session.mount("http://", FixedTokenAdapter())
            return session

        @sensitive_variables()
        def parse_id_token(self, token, nonce, **kwargs):
            return verify_login_token(
                token.get("id_token"),
                jwks=configuration.keys_for_token(token.get("id_token")),
                issuer=configuration.issuer,
                audience=configuration.client_id,
                nonce=nonce,
                access_token=token.get("access_token"),
            )

    return StrictDjangoClient(
        framework=ShortStateIntegration("signalbridge"),
        name="signalbridge",
        client_id=configuration.client_id,
        authorize_url=AUTHORIZATION,
        access_token_url=TOKEN,
        client_kwargs={
            "scope": "openid",
            "code_challenge_method": "S256",
            "token_endpoint_auth_method": "none",
            "default_timeout": 5,
        },
        issuer=configuration.issuer,
    )
