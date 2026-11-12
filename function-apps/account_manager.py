
import base64

import hashlib

import json

import logging

import os

import socket

import ssl

import traceback

import uuid

from datetime import datetime, timezone

from functools import lru_cache

from urllib.error import HTTPError, URLError

from urllib.parse import quote

from urllib.request import HTTPRedirectHandler, Request, build_opener


import azure.functions as func

from azure.identity import DefaultAzureCredential

from azure.keyvault.secrets import SecretClient


from configuration import CONFIG


bp = func.Blueprint()

IDENTITY_BASE = "https://identity-api.example.invalid/v1/users"

TICKETING_URLS = {

    "production": "https://tickets.example.invalid/api/v1/orders",

    "test": "https://tickets-test.example.invalid/api/v1/orders",

}

VALID_ACTIONS = {"Disable", "DisableReset", "Enable"}

HTTP_TIMEOUT_SECONDS = 30

MAX_RESPONSE_BYTES = 2 * 1024 * 1024

LOGGER = logging.getLogger(__name__)


class NoRedirects(HTTPRedirectHandler):

    """Never forward service credentials to redirected destinations."""


    def redirect_request(self, req, fp, code, msg, headers, newurl):

        return None


OPENER = build_opener(NoRedirects())


def code_version():

    """Fingerprint the deployed generic_account_handler.py automatically on every request.


    A change to this file produces a new fingerprint without manual version edits.

    This is a source-file fingerprint, not a Git commit or whole-app release ID.

    """

    try:

        with open(__file__, "rb") as source_file:

            return hashlib.sha256(source_file.read()).hexdigest()[:16]

    except OSError:

        LOGGER.warning("Unable to calculate generic_account_handler.py code fingerprint")

        return "unavailable"


def outbound_ip_diagnostic():

    """Best-effort public egress IP check for the test response only.


    This is the IP observed by a generic diagnostic endpoint, not necessarily the IP identitySystem sees.

    No secrets, headers, or account data are sent to the diagnostic service.

    """

    try:

        request = Request(

            "https://egress-check.example.invalid/ip",

            headers={"Accept": "application/json"},

            method="GET",

        )

        with OPENER.open(request, timeout=5) as result:

            data = json.loads(result.read(1024).decode("utf-8"))

        ip = data.get("ip")

        if not isinstance(ip, str) or not ip:

            raise ValueError("IP service returned no IP")

        return {"outboundIp": ip, "outboundIpSource": "a configured egress diagnostic endpoint"}

    except Exception as exc:

        return {

            "outboundIp": None,

            "outboundIpError": type(exc).__name__,

        }


def debug_enabled():

    """Only allow additional diagnostics during explicitly enabled local development."""

    return (

        os.environ.get("APP_ENVIRONMENT", "").lower() == "development"

        and os.environ.get("APP_DEBUG_ERRORS", "").lower() in ("true", "1")

    )


def json_response(body, status=200, extra_headers=None):

    return func.HttpResponse(

        json.dumps(body), status_code=status, mimetype="application/json",

        headers=extra_headers,

    )


def safe_exception_details(exc):

    """Return diagnostic metadata only; never echo SDK exception messages or credentials."""

    details = {"exceptionType": type(exc).__name__}

    if isinstance(exc, HTTPError):

        details["upstreamHttpStatus"] = exc.code

    if isinstance(exc, (TimeoutError, socket.timeout)):

        details["category"] = "timeout"

    elif isinstance(exc, socket.gaierror):

        details["category"] = "dns"

        details["dnsErrorCode"] = exc.errno

    elif isinstance(exc, ssl.SSLError):

        details["category"] = "tls"

        details["sslReason"] = str(getattr(exc, "reason", ""))[:100]

    elif isinstance(exc, URLError):

        reason = getattr(exc, "reason", None)

        details["category"] = "network"

        details["networkReasonType"] = type(reason).__name__

        if isinstance(reason, OSError):

            details["osErrorCode"] = reason.errno

            if isinstance(getattr(reason, "strerror", None), str):

                details["osReason"] = reason.strerror[:160]

    elif isinstance(exc, OSError):

        details["category"] = "os"

        details["osErrorCode"] = exc.errno

    else:

        details["category"] = "application_or_sdk"

        for attribute in ("status_code", "error_code"):

            value = getattr(exc, attribute, None)

            if isinstance(value, (str, int)) and len(str(value)) < 80:

                details[attribute] = value

    # File basenames and line numbers are enough to diagnose the failing statement.

    # Don't include source lines, local variables, exception text, auth headers or URLs.

    frames = traceback.extract_tb(exc.__traceback__)

    details["trace"] = [

        {"file": os.path.basename(frame.filename), "function": frame.name, "line": frame.lineno}

        for frame in frames[-6:]

    ]

    return details


def failure(message, status, stage, exc=None, *, partial_success=False,

            upstream_status=None, upstream_content_type=None):

    """Uniform JSON errors with a diagnostic ID and a safe stage identifier."""

    diagnostic_id = uuid.uuid4().hex

    data = {

        "success": False,

        "error": message,

        "stage": stage,

        "diagnosticId": diagnostic_id,

        "codeVersion": code_version(),

        "partialSuccess": partial_success,

    }

    if upstream_status is not None:

        data["upstreamStatus"] = upstream_status

    if debug_enabled():

        if upstream_content_type:

            data["upstreamContentType"] = upstream_content_type.split(";", 1)[0]

        if exc is not None:

            data["debug"] = safe_exception_details(exc)

    LOGGER.error(

        "Account manager error id=%s stage=%s type=%s status=%s partialSuccess=%s",

        diagnostic_id, stage, type(exc).__name__ if exc else "upstream_or_validation",

        upstream_status if upstream_status is not None else status, partial_success,

    )

    return json_response(data, status)


def upstream_response(status, raw, content_type):

    """Pass through successful identitySystem responses without fabricating user details."""

    return func.HttpResponse(

        body=raw, status_code=status,

        mimetype=content_type.split(";", 1)[0] or "application/json",

        headers={"X-Response-Origin": "IDENTITY_PROVIDER_TOKEN"},

    )


def parsed_body(raw):

    if not raw:

        return None

    try:

        return json.loads(raw.decode("utf-8-sig"))

    except (UnicodeDecodeError, ValueError):

        return raw.decode("utf-8", errors="replace")


@lru_cache(maxsize=1)

def secrets_client():

    vault_name = CONFIG["secretStoreName"]

    vault_url = f"https://{vault_name}.vault.azure.net/"

    return SecretClient(vault_url=vault_url, credential=DefaultAzureCredential())


def get_secret(client, name):

    value = client.get_secret(name).value

    if not isinstance(value, str) or not value:

        raise RuntimeError(f"Required secret {name} is empty")

    return value


def call_http(method, url, headers, body=None, basic_auth=None):

    """Return (status, raw bytes, content type); never log credentials or URLs."""

    request_headers = dict(headers)

    if basic_auth is not None:

        user, password = basic_auth

        encoded = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")

        request_headers["Authorization"] = "Basic " + encoded

    payload = None if body is None else json.dumps(body).encode("utf-8")

    req = Request(url, headers=request_headers, data=payload, method=method)

    try:

        with OPENER.open(req, timeout=HTTP_TIMEOUT_SECONDS) as result:

            return (result.status, result.read(MAX_RESPONSE_BYTES + 1),

                    result.headers.get("Content-Type", "application/json"))

    except HTTPError as error:

        with error:

            return (error.code, error.read(MAX_RESPONSE_BYTES + 1),

                    error.headers.get("Content-Type", "application/json"))


def validate_request(body):

    if not isinstance(body, dict):

        raise ValueError("JSON object required")

    username = body.get("username")

    if not isinstance(username, str) or not username.strip() or len(username) > 256:

        raise ValueError("Missing or invalid username")

    if username != username.strip() or "/" in username or "\\\\" in username:

        raise ValueError("Invalid username")

    method = body.get("method")

    if not isinstance(method, str) or method.upper() not in {"GET", "PATCH"}:

        raise ValueError("Invalid method. Supported methods are GET and PATCH.")

    method = method.upper()

    action = body.get("action")

    if method == "PATCH" and (not isinstance(action, str) or action not in VALID_ACTIONS):

        raise ValueError("Invalid action. Supported actions are Disable, DisableReset, and Enable.")

    if method == "PATCH" and action in {"Disable", "DisableReset"}:

        target = body.get("ticketingTarget", CONFIG.get("defaultTicketingTarget"))

        if not isinstance(target, str) or target.lower() not in TICKETING_URLS:

            raise ValueError("Invalid ticketing target. Supported targets are production and test.")

        for field in ("description", "reference"):

            if not isinstance(body.get(field, ""), str):

                raise ValueError(f"Invalid {field}")

    return username, method, action


def handle_request(req, *, vip_only=False):

    stage = "parse_request"

    try:

        try:

            body = req.get_json()

        except ValueError as exc:

            return failure("Invalid or missing JSON payload", 400, stage, exc)


        if isinstance(body, dict):

            if vip_only and "target" in body:

                return failure("external integration requests must not include target", 400, "validate_request")

            if "test" in body:

                if set(body) != {"test"} or body["test"] is not True:

                    return failure("Send only test: true for a connectivity check", 400, "validate_request")

                return json_response({

                    "success": True,

                    "message": "Example-Account-Workflow is reachable",

                    "codeVersion": code_version(),

                    "timestamp": datetime.now(timezone.utc).isoformat(),

                    **outbound_ip_diagnostic(),

                })

            if set(body) == {"probe"} and body["probe"] is True:

                return json_response({"probe": True})

            if "probe" in body:

                return failure("Send only probe: true for a probe", 400, "validate_request")


        stage = "validate_request"

        try:

            username, method, action = validate_request(body)

        except ValueError as exc:

            return failure(str(exc), 400, stage, exc)


        patch_completed = False

        stage = "key_vault_client"

        client = secrets_client()

        stage = "key_vault_identity_secret"

        identity_token = get_secret(client, "IDENTITY_PROVIDER_TOKEN")

        url = f"{IDENTITY_BASE}/{quote(username, safe='')}/Account"

        headers = {

            "Accept": "application/json", "Content-Type": "application/json",

            "X-API-Key": identity_token,

        }

        ticket_target = None

        ticket_password = None

        if method == "PATCH" and action in {"Disable", "DisableReset"}:

            ticket_target = body.get("ticketingTarget", CONFIG.get("defaultTicketingTarget")).lower()

            stage = "key_vault_ticketing_secret"

            ticket_password = get_secret(client, "TICKETING_PROVIDER_PASSWORD")


        stage = "identity_get"

        get_status, get_raw, get_type = call_http("GET", url, headers)

        if len(get_raw) > MAX_RESPONSE_BYTES:

            return failure("identitySystem response too large", 502, stage)

        if not 200 <= get_status < 300:

            return failure("identitySystem GET returned an error", get_status, stage,

                           upstream_status=get_status, upstream_content_type=get_type)

        if method == "GET":

            return upstream_response(get_status, get_raw, get_type)


        stage = "identity_patch"

        patch_status, patch_raw, patch_type = call_http(

            "PATCH", url, headers, body={"action": action}

        )

        if len(patch_raw) > MAX_RESPONSE_BYTES:

            return failure("identitySystem PATCH response too large; outcome requires verification",

                           502, stage, partial_success=False)

        if patch_status != 200:

            return failure("identitySystem PATCH returned an unexpected status; outcome requires verification",

                           patch_status, stage, partial_success=200 <= patch_status < 300,

                           upstream_status=patch_status, upstream_content_type=patch_type)

        if action == "Enable":

            return upstream_response(patch_status, patch_raw, patch_type)

        patch_completed = True


        ticket_payload = {

            "quantity": 1,

            "variables": {

                "subject_id": username,

                "description": body.get("description", ""),

                "reference": body.get("reference", ""),

            },

        }

        stage = "ticketing_order"

        ticket_status, ticket_raw, ticket_type = call_http(

            "POST", TICKETING_URLS[ticket_target],

            {"Accept": "application/json", "Content-Type": "application/json"},

            body=ticket_payload, basic_auth=("integration_account", ticket_password),

        )

        if len(ticket_raw) > MAX_RESPONSE_BYTES:

            return failure("Ticketing service response too large; order outcome requires verification",

                           502, stage, partial_success=True)

        if not 200 <= ticket_status < 300:

            return failure("identitySystem update succeeded, but ticketing service order failed",

                           502, stage, partial_success=True, upstream_status=ticket_status,

                           upstream_content_type=ticket_type)

        return json_response({"IDENTITY_PROVIDER_TOKEN": parsed_body(patch_raw),

                              "ticketingPlatform": parsed_body(ticket_raw)}, 200)


    except (URLError, TimeoutError, OSError) as exc:

        return failure("Upstream connection failed" + ("; operation outcome requires verification" if stage in ("identity_patch", "ticketing_order") else ""),

                       502, stage, exc, partial_success=locals().get("patch_completed", False))

    except Exception as exc:

        return failure("Internal integration error" + ("; operation outcome requires verification" if stage in ("identity_patch", "ticketing_order") else ""),

                       502, stage, exc, partial_success=locals().get("patch_completed", False))


@bp.function_name(name="user_generic_account_handler")

@bp.route(route=CONFIG["routes"]["genericAccountHandler"], methods=["POST"],

          auth_level=func.AuthLevel.FUNCTION)

def user_generic_account_handler(req: func.HttpRequest) -> func.HttpResponse:

    return handle_request(req)
