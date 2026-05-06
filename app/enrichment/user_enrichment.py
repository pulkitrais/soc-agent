"""
User Enrichment
Queries Microsoft Graph API for user and sign-in risk information.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from app.config import get_settings

logger = logging.getLogger(__name__)


async def enrich_user(upn_or_id: str) -> dict[str, Any]:
    """
    Enrich a user principal name or Object ID using Microsoft Graph.

    Returns basic profile info, manager, group memberships, and risk level.
    """
    settings = get_settings()
    result: dict[str, Any] = {
        "user": upn_or_id,
        "profile": {},
        "risk_info": {},
        "groups": [],
        "summary": {},
    }

    try:
        from msgraph import GraphServiceClient
        from azure.identity import ChainedTokenCredential
        from app.auth.azure_auth import get_auth_manager, GRAPH_SCOPE

        credential = get_auth_manager().get_credential()
        graph_client = GraphServiceClient(credentials=credential)

        # Profile
        user = await graph_client.users.by_user_id(upn_or_id).get()
        if user:
            result["profile"] = {
                "id": user.id,
                "display_name": user.display_name,
                "upn": user.user_principal_name,
                "mail": user.mail,
                "job_title": user.job_title,
                "department": user.department,
                "office_location": user.office_location,
                "account_enabled": user.account_enabled,
                "created_datetime": str(user.created_date_time) if user.created_date_time else "",
            }

        # Risk info
        try:
            risky = await graph_client.identity_protection.risky_users.by_risky_user_id(
                user.id
            ).get()
            if risky:
                result["risk_info"] = {
                    "risk_level": str(risky.risk_level),
                    "risk_state": str(risky.risk_state),
                    "risk_last_updated": str(risky.risk_last_updated_date_time),
                }
        except Exception:
            pass  # Risk info may not be available in all tenants

        # Group memberships (first 20)
        groups_resp = await graph_client.users.by_user_id(user.id).member_of.get()
        if groups_resp and groups_resp.value:
            result["groups"] = [
                g.display_name for g in groups_resp.value[:20] if hasattr(g, "display_name")
            ]

        result["summary"] = {
            "found": True,
            "account_enabled": result["profile"].get("account_enabled"),
            "risk_level": result["risk_info"].get("risk_level", "none"),
            "group_count": len(result["groups"]),
        }

    except ImportError:
        result["summary"]["note"] = "msgraph-sdk not installed."
    except Exception as exc:
        logger.warning("Graph user enrichment failed for %s: %s", upn_or_id, exc)
        result["summary"]["error"] = str(exc)

    return result
