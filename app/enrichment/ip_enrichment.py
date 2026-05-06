"""
IP Enrichment
Queries VirusTotal and AbuseIPDB for IP reputation data.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any, Optional

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)

# Request timeout (seconds)
_TIMEOUT = 15.0


def is_private_ip(ip: str) -> bool:
    """Return True if the IP is RFC1918 private, loopback, or not a valid IP address."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True  # Treat invalid/unresolvable strings as non-public (safe default)


async def enrich_ip(ip: str) -> dict[str, Any]:
    """
    Asynchronously enrich an IP address using VirusTotal and AbuseIPDB.

    Returns a merged dict with keys:
        ip, is_private, virustotal, abuseipdb, summary
    """
    settings = get_settings()
    result: dict[str, Any] = {
        "ip": ip,
        "is_private": is_private_ip(ip),
        "virustotal": {},
        "abuseipdb": {},
        "summary": {},
    }

    if result["is_private"]:
        result["summary"]["note"] = "Private/Internal IP — external enrichment skipped."
        return result

    vt_task = _virustotal_ip(ip, settings.virustotal_api_key) if settings.virustotal_api_key else None
    abuse_task = _abuseipdb_ip(ip, settings.abuseipdb_api_key) if settings.abuseipdb_api_key else None

    # Run both checks concurrently, defaulting to empty dicts when API keys are absent
    import asyncio

    async def _empty() -> dict:
        return {}

    vt_data, abuse_data = await asyncio.gather(
        vt_task if vt_task is not None else _empty(),
        abuse_task if abuse_task is not None else _empty(),
    )

    result["virustotal"] = vt_data
    result["abuseipdb"] = abuse_data

    # Build summary
    malicious_vt = vt_data.get("malicious_count", 0)
    abuse_score = abuse_data.get("abuse_confidence_score", 0)
    country = abuse_data.get("country_code") or vt_data.get("country", "Unknown")

    if malicious_vt > 5 or abuse_score > 75:
        threat_level = "high"
    elif malicious_vt > 0 or abuse_score > 25:
        threat_level = "medium"
    else:
        threat_level = "low"

    result["summary"] = {
        "threat_level": threat_level,
        "country": country,
        "malicious_engines": malicious_vt,
        "abuse_score": abuse_score,
    }

    return result


async def _virustotal_ip(ip: str, api_key: str) -> dict[str, Any]:
    """Query VirusTotal for IP reputation."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "malicious_count": stats.get("malicious", 0),
                "suspicious_count": stats.get("suspicious", 0),
                "harmless_count": stats.get("harmless", 0),
                "country": attrs.get("country", ""),
                "asn": attrs.get("asn", ""),
                "as_owner": attrs.get("as_owner", ""),
                "reputation": attrs.get("reputation", 0),
            }
    except Exception as exc:
        logger.warning("VirusTotal IP lookup failed for %s: %s", ip, exc)
        return {"error": str(exc)}


async def _abuseipdb_ip(ip: str, api_key: str) -> dict[str, Any]:
    """Query AbuseIPDB for IP reputation."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(url, headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return {
                "ip_address": data.get("ipAddress", ip),
                "is_public": data.get("isPublic", True),
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "country_code": data.get("countryCode", ""),
                "isp": data.get("isp", ""),
                "domain": data.get("domain", ""),
                "total_reports": data.get("totalReports", 0),
                "last_reported_at": data.get("lastReportedAt", ""),
                "is_tor": data.get("isTor", False),
            }
    except Exception as exc:
        logger.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)
        return {"error": str(exc)}
