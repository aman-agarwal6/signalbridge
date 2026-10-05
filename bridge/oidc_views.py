"""Opt-in fixed-lab OIDC routes. Browser mutations elsewhere retain CSRF."""

import logging
import re
import secrets

from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables

from integrations.identity.client import create_client
from integrations.identity.configuration import load_configuration
from integrations.identity.protocol import TokenRejected, verify_logout_token

from .federation import FederationDenied, VerifiedIdentity, admit_verified_identity
from .oidc_state import (
    begin_exchange,
    consume_exchange,
    consume_verified_logout,
    reserve_protocol_request,
)

log = logging.getLogger(__name__)


def _response(status):
    response = HttpResponse(
        "Identity request completed."
        if status == 200
        else "Identity request could not be completed.",
        status=status,
        content_type="text/plain",
    )
    response["Cache-Control"] = "no-store"
    response["Referrer-Policy"] = "no-referrer"
    return response


def _guard(request):
    if not settings.FEDERATED_AUTH_ENABLED:
        return _response(404)
    if not request.is_secure() or request.get_host() != "127.0.0.1:18842":
        return _response(400)
    if request.method != "POST":
        return _response(405)
    if request.META.get("QUERY_STRING"):
        return _response(400)
    return None


def _form(request, *, maximum, allowed, required):
    if request.content_type != "application/x-www-form-urlencoded" or len(request.body) > maximum:
        raise FederationDenied()
    if request.FILES or set(request.POST) - allowed or not required.issubset(request.POST):
        raise FederationDenied()
    if any(len(request.POST.getlist(key)) != 1 for key in request.POST):
        raise FederationDenied()
    return request.POST


def _failure(error):
    # Never log provider messages, callback values or exception tracebacks.
    # The optional check is a fixed source coordinate set by the validator.
    check = getattr(error, "check", None)
    if type(check) is str and re.fullmatch(r"protocol\.py:[0-9]{1,5}", check):
        log.warning("Identity request rejected (%s at %s).", type(error).__name__, check)
    else:
        log.warning("Identity request rejected (%s).", type(error).__name__)
    return _response(403 if isinstance(error, (FederationDenied, TokenRejected)) else 503)


@csrf_protect
@sensitive_variables()
def start(request):
    denied = _guard(request)
    if denied is not None:
        return denied
    try:
        if request.body and (
            set(request.POST) - {"csrfmiddlewaretoken"} or len(request.body) > 256
        ):
            raise FederationDenied()
        configuration = load_configuration()
        client = create_client(configuration)
        state = begin_exchange(request, configuration.issuer)
        return client.authorize_redirect(
            request,
            configuration.callback,
            state=state,
            nonce=secrets.token_urlsafe(32),
            code_verifier=secrets.token_urlsafe(48),
            response_mode="form_post",
            max_age=300,
            acr_values="2",
        )
    except Exception as error:
        return _failure(error)


@csrf_exempt
@sensitive_post_parameters()
@sensitive_variables()
def callback(request):
    denied = _guard(request)
    if denied is not None:
        return denied
    try:
        configuration = load_configuration()
        values = _form(
            request,
            maximum=4096,
            allowed={
                "code",
                "state",
                "iss",
                "session_state",
                "error",
                "error_description",
                "error_uri",
            },
            required={"state"},
        )
        reserve_protocol_request()
        consume_exchange(request, configuration.issuer, values["state"])
        client = create_client(configuration)
        try:
            if (
                "error" in values
                or values.get("iss", configuration.issuer) != configuration.issuer
                or not re.fullmatch(r"[A-Za-z0-9._~-]{1,2048}", values.get("code", ""))
            ):
                raise FederationDenied()
            token = client.authorize_access_token(request, leeway=5)
            evidence = token.get("userinfo")
            if not isinstance(evidence, VerifiedIdentity):
                raise FederationDenied()
            admit_verified_identity(request, evidence)
        finally:
            client.framework.clear_state_data(request.session, values["state"])
            request.session.save()
        response = HttpResponseRedirect("/")
        response["Referrer-Policy"] = "no-referrer"
        response["Cache-Control"] = "no-store"
        return response
    except Exception as error:
        return _failure(error)


@csrf_exempt
@sensitive_post_parameters()
@sensitive_variables()
def backchannel(request):
    denied = _guard(request)
    if denied is not None:
        return denied
    try:
        configuration = load_configuration()
        values = _form(request, maximum=16384, allowed={"logout_token"}, required={"logout_token"})
        reserve_protocol_request()
        evidence = verify_logout_token(
            values["logout_token"],
            jwks=configuration.keys_for_token(values["logout_token"]),
            issuer=configuration.issuer,
            audience=configuration.client_id,
        )
        consume_verified_logout(evidence)
        return _response(200)
    except Exception as error:
        return _failure(error)
