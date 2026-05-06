"""
Azure Authentication Module
Supports: Device Code Flow, Service Principal, Managed Identity.
Credentials are cached in memory during the session.
"""

from __future__ import annotations

import logging
from typing import Optional

from azure.identity import (
    ChainedTokenCredential,
    ClientSecretCredential,
    DeviceCodeCredential,
    ManagedIdentityCredential,
)
from azure.identity import CredentialUnavailableError

from app.config import Settings, get_settings

logger = logging.getLogger(__name__)

# Azure Monitor scope required for Log Analytics queries
AZURE_MONITOR_SCOPE = "https://api.loganalytics.io/.default"
AZURE_MGMT_SCOPE = "https://management.azure.com/.default"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"


class AzureAuthManager:
    """Manages Azure credential lifecycle for the application."""

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self._settings = settings or get_settings()
        self._credential = None

    # ── Public API ────────────────────────────────────────────────────────────

    def get_credential(self):
        """Return a cached (or newly created) Azure credential object."""
        if self._credential is None:
            self._credential = self._build_credential()
        return self._credential

    def test_credential(self) -> bool:
        """Attempt to acquire a token to verify credentials work."""
        try:
            cred = self.get_credential()
            token = cred.get_token(AZURE_MONITOR_SCOPE)
            return bool(token and token.token)
        except Exception as exc:
            logger.warning("Credential test failed: %s", exc)
            return False

    def invalidate(self) -> None:
        """Clear cached credential (forces re-auth on next call)."""
        self._credential = None

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _build_credential(self):
        method = self._settings.azure_auth_method
        logger.info("Building Azure credential using method: %s", method)

        if method == "service_principal":
            return self._service_principal_credential()
        elif method == "managed_identity":
            return ManagedIdentityCredential()
        else:
            # Default: device code flow (interactive)
            return self._device_code_credential()

    def _service_principal_credential(self) -> ClientSecretCredential:
        s = self._settings
        if not all([s.azure_tenant_id, s.azure_client_id, s.azure_client_secret]):
            raise ValueError(
                "Service principal auth requires AZURE_TENANT_ID, "
                "AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET to be set."
            )
        return ClientSecretCredential(
            tenant_id=s.azure_tenant_id,
            client_id=s.azure_client_id,
            client_secret=s.azure_client_secret,
        )

    def _device_code_credential(self) -> DeviceCodeCredential:
        kwargs = {}
        if self._settings.azure_tenant_id:
            kwargs["tenant_id"] = self._settings.azure_tenant_id
        if self._settings.azure_client_id:
            kwargs["client_id"] = self._settings.azure_client_id
        return DeviceCodeCredential(**kwargs)


# Module-level singleton for convenience
_auth_manager: Optional[AzureAuthManager] = None


def get_auth_manager() -> AzureAuthManager:
    """Return the module-level singleton auth manager."""
    global _auth_manager
    if _auth_manager is None:
        _auth_manager = AzureAuthManager()
    return _auth_manager


def reset_auth_manager() -> None:
    """Reset the singleton (useful for testing or re-auth flows)."""
    global _auth_manager
    _auth_manager = None
