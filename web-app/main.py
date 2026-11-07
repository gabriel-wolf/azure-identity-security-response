
import json
import logging
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from zoneinfo import ZoneInfo

import requests
from azure.core.exceptions import AzureError
from fastapi import FastAPI, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from identity_apim import get_user_status, call_identity_api
from entra_users import get_entra_user


app = FastAPI()
templates = Jinja2Templates(directory="templates")
logger = logging.getLogger(__name__)

@app.get("/styles.css", include_in_schema=False)
def get_stylesheet():
    return FileResponse(
        Path(__file__).resolve().parent
        / "templates"
        / "styles.css",
        media_type="text/css",
    )

DEBUG_UI = os.getenv(
    "IDENTITY_DEBUG_UI", "false"
).lower() == "true"

CSRF_COOKIE = "__Host-identity-csrf"


# Account actions and their respective APIM endpoints.
ACCOUNT_ACTIONS = {
    "disable_reset": {
        "action": "DisableReset",
        "url_setting": "IDENTITY_APIM_DISABLE_URL",
        "expected_status": "DISABLED",
    },
    "enable": {
        "action": "Enable",
        "url_setting": "IDENTITY_APIM_ENABLE_URL",
        "expected_status": "ACTIVE",
    },
    "disable_no_reset": {
        "action": "Disable",
        "url_setting": "IDENTITY_APIM_DISABLE_URL",
        "expected_status": "DISABLED",
    },
}


def get_deployment_time():
    try:
        path = (
            Path(__file__).resolve().parent
            / "deployment_timestamp.txt"
        )

        timestamp = path.read_text(
            encoding="utf-8"
        ).strip()

        utc_time = datetime.strptime(
            timestamp,
            "%Y-%m-%d %H:%M:%S UTC"
        ).replace(tzinfo=timezone.utc)

        chicago_time = utc_time.astimezone(
            ZoneInfo("America/Chicago")
        )

        return chicago_time.strftime(
            "%m/%d/%Y %I:%M:%S %p %Z"
        )

    except (OSError, UnicodeError, ValueError):
        logger.warning(
            "Startup timestamp missing or invalid",
            exc_info=True,
        )
        return "Not recorded"


def get_vip_titles():
    titles = json.loads(
        os.environ["IDENTITY_VIP_TITLES"]
    )

    if (
        not isinstance(titles, list)
        or not titles
        or not all(
            isinstance(title, str)
            and title.strip()
            for title in titles
        )
    ):
        raise ValueError(
            "IDENTITY_VIP_TITLES must be a nonempty "
            "JSON list of strings"
        )

    return titles


def check_vip(job_title):
    titles = get_vip_titles()

    if (
        not isinstance(job_title, str)
        or not job_title.strip()
    ):
        return {
            "is_vip": None,
            "matched_titles": [],
        }

    matches = [
        title
        for title in titles
        if title.strip().casefold()
        in job_title.casefold()
    ]

    return {
        "is_vip": bool(matches),
        "matched_titles": matches,
    }


def render_page(
    request,
    user=None,
    error=None,
    debug=None,
    searched=False,
    status_code=200,
):
    csrf_token = secrets.token_urlsafe(32)

    response = templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "user": user,
            "error": error,
            "debug": debug,
            "debug_enabled": DEBUG_UI,
            "searched": searched,
            "deployment_time": get_deployment_time(),
            "csrf_token": csrf_token,
        },
        status_code=status_code,
    )

    response.set_cookie(
        key=CSRF_COOKIE,
        value=csrf_token,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )

    return response


def normalize_identity_result(result):
    if not isinstance(result, dict):
        raise ValueError("Invalid Identity response")

    if "error" in result:
        raise ValueError("Identity returned an error")

    username = result.get("username")

    if (
        not isinstance(username, str)
        or not username.strip()
    ):
        raise ValueError(
            "Identity did not return a valid username"
        )

    return username.strip()


def build_request_details(
    url,
    endpoint_setting,
    payload,
):
    """
    Capture the application-to-APIM request
    without exposing authentication credentials
    or URL query parameters.
    """

    parsed_url = urlsplit(url)

    safe_url = urlunsplit((
        parsed_url.scheme,
        parsed_url.netloc,
        parsed_url.path,
        "",
        "",
    ))

    return {
        "http_method": "POST",
        "target_url": safe_url,
        "endpoint_setting": endpoint_setting,
        "headers": {
            "Content-Type": "application/json",
            "Authorization": "[REDACTED]",
            "Ocp-Apim-Subscription-Key": "[REDACTED]",
        },
        "body": payload.copy(),
    }


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return render_page(request)


@app.post("/lookup", response_class=HTMLResponse)
def lookup_user(
    request: Request,
    username: str = Form(...),
):
    username = username.strip()

    if not username:
        return render_page(
            request,
            error="Please enter a username.",
            searched=True,
        )

    debug = None

    try:
        # Step 1: Lookup through Identity/APIM.
        result, debug = get_user_status(
            username,
            include_debug=DEBUG_UI,
        )

        # Step 2: Resolve canonical Identity username.
        identity_username = normalize_identity_result(
            result
        )

        # Step 3: Lookup Entra information.
        entra_user = get_entra_user(
            identity_username
        )

        # Step 4: Process account status.
        status = str(
            result.get("status") or "UNKNOWN"
        ).upper()

        if status not in ("ACTIVE", "DISABLED"):
            status = "UNKNOWN"

        # Step 5: Combine Identity and Entra data.
        user = {
            "username": identity_username,

            "display_name": entra_user.get(
                "display_name"
            ),
            "department": entra_user.get(
                "department"
            ),
            "job_title": entra_user.get(
                "job_title"
            ),

            "status": status,
            "disabled_date": (
                result.get("disabledDate")
                if status == "DISABLED"
                else None
            ),
            "pwd_last_set": result.get(
                "pwdLastSetDate"
            ),
        }

        # Step 6: VIP classification.
        vip_result = check_vip(
            user["job_title"]
        )

        user["is_vip"] = vip_result["is_vip"]
        user["vip_matches"] = vip_result[
            "matched_titles"
        ]

        return render_page(
            request,
            user=user,
            debug=debug,
            searched=True,
        )

    except (
        requests.RequestException,
        AzureError,
        ValueError,
        KeyError,
        TypeError,
    ):
        logger.exception("Account lookup failed")

        return render_page(
            request,
            error=(
                "Unable to retrieve complete account "
                "details. Check application logs. "
                "VIP status has not been verified."
            ),
            debug=debug,
            searched=True,
            status_code=502,
        )


def action_response(
    message,
    status_code,
    **extra,
):
    return JSONResponse(
        {
            "ok": False,
            "message": message,
            **extra,
        },
        status_code=status_code,
    )


@app.post("/account-action")
def account_action(request: Request, body: dict):

    # Verify CSRF token.
    cookie_token = request.cookies.get(
        CSRF_COOKIE
    )

    header_token = request.headers.get(
        "X-CSRF-Token"
    )

    if (
        not cookie_token
        or not header_token
        or not secrets.compare_digest(
            cookie_token,
            header_token,
        )
    ):
        return action_response(
            "Request verification failed. "
            "Reload the page and try again.",
            403,
        )

    username = body.get("username")
    action = body.get("action")

    if (
        not isinstance(username, str)
        or not username.strip()
    ):
        return action_response(
            "A username is required.",
            400,
        )

    if (
        not isinstance(action, str)
        or action not in ACCOUNT_ACTIONS
    ):
        return action_response(
            "Unsupported account action.",
            400,
        )

    username = username.strip()

    if len(username) > 320:
        return action_response(
            "Invalid username.",
            400,
        )

    # ServiceNow environment selection.
    service_now_target = body.get(
        "serviceNowTarget",
        "production",
    )

    if (
        not isinstance(service_now_target, str)
        or service_now_target not in (
            "production",
            "test",
        )
    ):
        return action_response(
            "Invalid ServiceNow target.",
            400,
        )

    action_config = ACCOUNT_ACTIONS[action]

    # Request details remain available when
    # an HTTP error occurs.
    request_details = None

    try:
        # Resolve username again on the server.
        current, _ = get_user_status(
            username
        )

        canonical_username = normalize_identity_result(
            current
        )

        # Re-check VIP status immediately before
        # a sensitive account operation.
        entra_user = get_entra_user(
            canonical_username
        )

        vip = check_vip(
            entra_user.get("job_title")
        )

        # Fail closed for protected or unverified
        # VIP accounts during disable operations.
        if action in (
            "disable_reset",
            "disable_no_reset",
        ):
            if vip["is_vip"] is not False:
                return action_response(
                    "Disable blocked: VIP account "
                    "detected or VIP status could "
                    "not be verified. Follow the "
                    "VIP handling procedure.",
                    403,
                )

        # Select the configured APIM endpoint.
        env_name = action_config[
            "url_setting"
        ]

        url = os.environ[env_name]

        # Build the API request body.
        # HTTP method to APIM: POST
        # JSON method property: PATCH
        payload = {
            "username": canonical_username,
            "method": "PATCH",
            "action": action_config["action"],
            "description": "Identity security response",
            "reference": "Identity Response Platform",
            "serviceNowTarget": service_now_target,
        }

        # Record the exact application-to-APIM
        # request without revealing secrets.
        request_details = build_request_details(
            url=url,
            endpoint_setting=env_name,
            payload=payload,
        )

        logger.info(
            "Submitting account action=%s "
            "username=%s ServiceNow=%s "
            "APIM endpoint=%s",
            action,
            canonical_username,
            service_now_target,
            request_details["target_url"],
        )

        # Send POST request to APIM.
        result, _ = call_identity_api(
            url,
            payload,
            http_method="POST",
        )

        # Detect business-level failures even
        # when HTTP status is successful.
        backend_failed = (
            isinstance(result, dict)
            and (
                result.get("success") is False
                or result.get("ok") is False
                or (
                    isinstance(
                        result.get("error"), str
                    )
                    and bool(result["error"])
                )
                or str(
                    result.get("status", "")
                ).lower() in (
                    "failed",
                    "error",
                )
            )
        )

        if backend_failed:
            return action_response(
                "APIM responded, but the backend "
                "reported an error.",
                502,
                request_details=request_details,
                backend_response=result,
                service_now_target=service_now_target,
            )

        # Verify resulting account status.
        verification = {
            "verified": False,
            "status": None,
            "message": (
                "The action request was accepted. "
                "Account state has not been verified."
            ),
        }

        try:
            latest, _ = get_user_status(
                canonical_username
            )

            if (
                not isinstance(latest, dict)
                or "error" in latest
            ):
                raise ValueError(
                    "Invalid verification response"
                )

            observed_status = str(
                latest.get("status") or "UNKNOWN"
            ).upper()

            expected = action_config[
                "expected_status"
            ]

            verified = (
                observed_status == expected
            )

            verification = {
                "verified": verified,
                "status": observed_status,
                "message": (
                    "Identity confirms the expected "
                    "account status."
                    if verified
                    else
                    "Identity does not yet show the "
                    "expected account status. "
                    "It may need time to update."
                ),
            }

        except (
            requests.RequestException,
            AzureError,
            ValueError,
            KeyError,
            TypeError,
        ):
            logger.exception(
                "Post-action verification failed"
            )

            verification["message"] = (
                "APIM returned successfully, but "
                "the follow-up status lookup failed."
            )

        logger.info(
            "Account action %s returned for %s; "
            "verified=%s; ServiceNow=%s",
            action,
            canonical_username,
            verification["verified"],
            service_now_target,
        )

        return JSONResponse({
            "ok": True,
            "message": (
                "APIM returned a successful HTTP "
                "response for the action."
            ),
            "action": action,
            "username": canonical_username,
            "service_now_target": service_now_target,
            "request_details": request_details,
            "backend_response": result,
            "verification": verification,
        })

    except requests.HTTPError as exc:
        logger.exception(
            "APIM action HTTP failure"
        )

        response = exc.response

        return action_response(
            "APIM returned an HTTP error.",
            502,
            request_details=request_details,
            service_now_target=service_now_target,
            upstream_status=(
                response.status_code
                if response is not None
                else None
            ),
            backend_response=(
                response.text[:2000]
                if response is not None
                else None
            ),
        )

    except (
        requests.RequestException,
        AzureError,
        ValueError,
        KeyError,
        TypeError,
    ):
        logger.exception(
            "Account action failed"
        )

        return action_response(
            "Account action failed before a "
            "successful response was received. "
            "Check application logs and verify "
            "account status before retrying.",
            502,
            request_details=request_details,
            service_now_target=service_now_target,
        )


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "application": "Azure Identity Security Response Platform",
        "debug_enabled": DEBUG_UI,
    }
