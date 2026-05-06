"""
Enrichment package init - convenience wrapper for synchronous enrichment calls.
"""

from __future__ import annotations

import asyncio
from typing import Any

from app.enrichment.ip_enrichment import enrich_ip
from app.enrichment.hash_enrichment import enrich_hash
from app.enrichment.user_enrichment import enrich_user


def enrich_ip_sync(ip: str) -> dict[str, Any]:
    """Synchronous wrapper for IP enrichment (for use in Streamlit callbacks)."""
    return asyncio.run(enrich_ip(ip))


def enrich_hash_sync(hash_value: str) -> dict[str, Any]:
    """Synchronous wrapper for hash enrichment."""
    return asyncio.run(enrich_hash(hash_value))


def enrich_user_sync(upn: str) -> dict[str, Any]:
    """Synchronous wrapper for user enrichment."""
    return asyncio.run(enrich_user(upn))
