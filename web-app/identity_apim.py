
import os
import time
from urllib.parse import urlsplit

import requests
from azure.identity import ManagedIdentityCredential

credential = ManagedIdentityCredential()

IDENTITY_SCOPE = os.environ["IDENTITY_APIM_SCOPE"]


def call_identity_api(
    url: str,
    payload: dict,
    include_debug: bool = False,
    http_method: str = "POST",
) -> tuple[dict, dict | None]:

    token = credential.get_token(IDENTITY_SCOPE).token

    headers = {
        "Authorization": f"Bearer {token}",
        "Ocp-Apim-Subscription-Key": os.environ[
            "IDENTITY_APIM_SUBSCRIPTION_KEY"
        ],
        "Content-Type": "application/json",
    }

    started = time.perf_counter()

    response = requests.request(
        method=http_method,
        url=url,
        json=payload,
        headers=headers,
        timeout=60,
    )

    response.raise_for_status()

    elapsed_ms = round(
        (time.perf_counter() - started) * 1000
    )

    try:
        result = response.json()
    except ValueError:
        result = {
            "raw_response": response.text[:10000]
        }

    debug = None

    if include_debug:
        parsed = urlsplit(url)

        debug = {
            "request": {
                "method": http_method.upper(),
                "url": (
                    f"{parsed.scheme}://"
                    f"{parsed.netloc}{parsed.path}"
                ),
                "body": payload,
            },
            "response": {
                "status_code": response.status_code,
                "elapsed_ms": elapsed_ms,
                "body": result,
            },
        }

    return result, debug


def get_user_status(
    username: str,
    include_debug: bool = False,
):
    return call_identity_api(
        os.environ["IDENTITY_APIM_GET_URL"],
        {
            "username": username,
            "method": "GET",
        },
        include_debug=include_debug,
        http_method="POST",
    )

