"""
Hash Enrichment
Queries VirusTotal for file hash reputation.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)
_TIMEOUT = 15.0

# Hash type detection
_MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def detect_hash_type(hash_value: str) -> str:
    """Detect the type of hash string."""
    if _MD5_RE.match(hash_value):
        return "md5"
    elif _SHA1_RE.match(hash_value):
        return "sha1"
    elif _SHA256_RE.match(hash_value):
        return "sha256"
    return "unknown"


async def enrich_hash(hash_value: str) -> dict[str, Any]:
    """
    Enrich a file hash using VirusTotal.

    Returns:
        dict with keys: hash, hash_type, virustotal, summary
    """
    settings = get_settings()
    hash_type = detect_hash_type(hash_value)
    result: dict[str, Any] = {
        "hash": hash_value,
        "hash_type": hash_type,
        "virustotal": {},
        "summary": {},
    }

    if hash_type == "unknown":
        result["summary"]["error"] = "Unrecognised hash format (expected MD5/SHA1/SHA256)."
        return result

    if not settings.virustotal_api_key:
        result["summary"]["note"] = "VirusTotal API key not configured."
        return result

    vt_data = await _virustotal_hash(hash_value, settings.virustotal_api_key)
    result["virustotal"] = vt_data

    malicious = vt_data.get("malicious_count", 0)
    total = vt_data.get("total_engines", 0)

    if malicious > 10:
        threat_level = "critical"
    elif malicious > 3:
        threat_level = "high"
    elif malicious > 0:
        threat_level = "medium"
    else:
        threat_level = "clean"

    result["summary"] = {
        "threat_level": threat_level,
        "malicious_count": malicious,
        "total_engines": total,
        "malware_names": vt_data.get("popular_threat_classification", []),
        "file_name": vt_data.get("meaningful_name", ""),
    }
    return result


async def _virustotal_hash(hash_value: str, api_key: str) -> dict[str, Any]:
    """Query VirusTotal file report endpoint."""
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": api_key}
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 404:
                return {"not_found": True}
            resp.raise_for_status()
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            threat_cls = attrs.get("popular_threat_classification", {})
            names = [s.get("value") for s in threat_cls.get("suggested_threat_label", [])]
            return {
                "malicious_count": stats.get("malicious", 0),
                "suspicious_count": stats.get("suspicious", 0),
                "undetected_count": stats.get("undetected", 0),
                "total_engines": sum(stats.values()),
                "meaningful_name": attrs.get("meaningful_name", ""),
                "file_type": attrs.get("type_description", ""),
                "file_size": attrs.get("size", 0),
                "first_seen": attrs.get("first_submission_date", ""),
                "last_seen": attrs.get("last_analysis_date", ""),
                "popular_threat_classification": names,
            }
    except Exception as exc:
        logger.warning("VirusTotal hash lookup failed for %s: %s", hash_value, exc)
        return {"error": str(exc)}
