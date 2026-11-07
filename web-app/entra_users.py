
import logging

import requests
from azure.identity import ManagedIdentityCredential

logger = logging.getLogger(__name__)

credential = ManagedIdentityCredential()

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
GRAPH_URL = "https://graph.microsoft.com/v1.0/users"


def get_entra_user(username: str) -> dict:
    token = credential.get_token(GRAPH_SCOPE).token

    escaped_username = username.strip().replace("'", "''")

    response = requests.get(
        GRAPH_URL,
        headers={
            "Authorization": f"Bearer {token}",
            "ConsistencyLevel": "eventual",
        },
        params={
            "$filter": (
                "onPremisesSamAccountName eq "
                f"'{escaped_username}'"
            ),
            "$select": (
                "id,userPrincipalName,"
                "onPremisesSamAccountName,"
                "displayName,department,jobTitle"
            ),
            "$count": "true",
            "$top": "2",
        },
        timeout=20,
    )

    if not response.ok:
        # Log the Graph error, not the bearer token.
        logger.error(
            "Microsoft Graph lookup failed: "
            "HTTP %s, response: %.2000s",
            response.status_code,
            response.text,
        )

    response.raise_for_status()

    users = response.json().get("value", [])

    if len(users) == 0:
        raise ValueError(
            "User not found in Microsoft Entra ID"
        )

    if len(users) != 1:
        raise ValueError(
            "Multiple Entra users match this username"
        )

    user = users[0]

    return {
        "display_name": user.get("displayName"),
        "department": user.get("department"),
        "job_title": user.get("jobTitle"),
        "entra_id": user.get("id"),
    }
