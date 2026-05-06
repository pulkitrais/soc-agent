"""
Entity Enrichment page
Enriches IPs, file hashes, and users using threat intel APIs.
"""

from __future__ import annotations

import json

import streamlit as st

from app.enrichment import enrich_ip_sync, enrich_hash_sync, enrich_user_sync
from app.ui.components.visualizations import risk_gauge


def render() -> None:
    """Render the Enrichment page."""
    st.markdown("## 🔎 Entity Enrichment")
    st.markdown(
        "Enrich entities with threat intelligence from VirusTotal, AbuseIPDB, "
        "and Microsoft Graph."
    )
    st.divider()

    tabs = st.tabs(["🌐 IP Address", "🔑 File Hash", "👤 User"])

    # ── IP Enrichment ─────────────────────────────────────────────────────────
    with tabs[0]:
        st.markdown("### 🌐 IP Address Enrichment")
        ip_input = st.text_input(
            "IP Address:",
            placeholder="e.g. 8.8.8.8",
            key="enrich_ip",
        )
        if st.button("🔍 Enrich IP", use_container_width=True, key="btn_enrich_ip"):
            if not ip_input.strip():
                st.warning("Please enter an IP address.")
            else:
                with st.spinner("Enriching IP…"):
                    data = enrich_ip_sync(ip_input.strip())
                _display_ip_result(data)
                _save_enrichment_to_session(f"IP: {ip_input.strip()}", data)

    # ── Hash Enrichment ───────────────────────────────────────────────────────
    with tabs[1]:
        st.markdown("### 🔑 File Hash Enrichment")
        hash_input = st.text_input(
            "File Hash (MD5 / SHA1 / SHA256):",
            placeholder="e.g. 44d88612fea8a8f36de82e1278abb02f",
            key="enrich_hash",
        )
        if st.button("🔍 Enrich Hash", use_container_width=True, key="btn_enrich_hash"):
            if not hash_input.strip():
                st.warning("Please enter a file hash.")
            else:
                with st.spinner("Enriching hash…"):
                    data = enrich_hash_sync(hash_input.strip())
                _display_hash_result(data)
                _save_enrichment_to_session(f"Hash: {hash_input.strip()}", data)

    # ── User Enrichment ───────────────────────────────────────────────────────
    with tabs[2]:
        st.markdown("### 👤 User Enrichment")
        user_input = st.text_input(
            "User Principal Name or Object ID:",
            placeholder="e.g. john.doe@contoso.com",
            key="enrich_user",
        )
        if st.button("🔍 Enrich User", use_container_width=True, key="btn_enrich_user"):
            if not user_input.strip():
                st.warning("Please enter a UPN or Object ID.")
            else:
                with st.spinner("Enriching user via Microsoft Graph…"):
                    data = enrich_user_sync(user_input.strip())
                _display_user_result(data)
                _save_enrichment_to_session(f"User: {user_input.strip()}", data)


# ── Display helpers ───────────────────────────────────────────────────────────

def _display_ip_result(data: dict) -> None:
    summary = data.get("summary", {})
    threat_level = summary.get("threat_level", "unknown")

    col1, col2, col3 = st.columns(3)
    with col1:
        score = {"high": 80, "medium": 50, "low": 10}.get(threat_level, 0)
        st.plotly_chart(risk_gauge(score, "Threat Score"), use_container_width=True)
    with col2:
        st.metric("Country", summary.get("country", "Unknown"))
        st.metric("Abuse Score", f"{summary.get('abuse_score', 0)}/100")
    with col3:
        st.metric("VT Malicious Engines", summary.get("malicious_engines", 0))
        st.metric("Private IP", "Yes" if data.get("is_private") else "No")

    if data.get("abuseipdb"):
        with st.expander("AbuseIPDB Details"):
            abuse = data["abuseipdb"]
            cols = st.columns(3)
            cols[0].metric("ISP", abuse.get("isp", "N/A"))
            cols[1].metric("Total Reports", abuse.get("total_reports", 0))
            cols[2].metric("TOR Exit", "Yes" if abuse.get("is_tor") else "No")

    if data.get("virustotal"):
        with st.expander("VirusTotal Details"):
            vt = data["virustotal"]
            cols = st.columns(3)
            cols[0].metric("ASN", vt.get("asn", "N/A"))
            cols[1].metric("AS Owner", vt.get("as_owner", "N/A"))
            cols[2].metric("Reputation", vt.get("reputation", 0))


def _display_hash_result(data: dict) -> None:
    summary = data.get("summary", {})
    threat_level = summary.get("threat_level", "unknown")

    level_colors = {
        "critical": "🔴 CRITICAL",
        "high": "🟠 HIGH",
        "medium": "🟡 MEDIUM",
        "clean": "🟢 CLEAN",
    }
    st.markdown(f"### Verdict: {level_colors.get(threat_level, threat_level.upper())}")

    col1, col2 = st.columns(2)
    with col1:
        st.metric("Hash Type", data.get("hash_type", "unknown").upper())
        st.metric("File Name", summary.get("file_name", "Unknown"))
    with col2:
        mal = summary.get("malicious_count", 0)
        total = summary.get("total_engines", 0)
        st.metric("Detection Ratio", f"{mal}/{total}")

    if summary.get("malware_names"):
        st.markdown(f"**Malware names:** {', '.join(summary['malware_names'])}")

    if data.get("virustotal"):
        with st.expander("Full VirusTotal Report"):
            vt = data["virustotal"]
            st.json({k: v for k, v in vt.items() if k != "error"})


def _display_user_result(data: dict) -> None:
    profile = data.get("profile", {})
    risk = data.get("risk_info", {})

    if data.get("summary", {}).get("error"):
        st.error(f"Enrichment error: {data['summary']['error']}")
        return

    if not profile:
        st.warning("User not found or Graph not available.")
        return

    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f"**{profile.get('display_name', 'Unknown')}**")
        st.markdown(f"*{profile.get('job_title', 'N/A')} — {profile.get('department', 'N/A')}*")
        st.metric("Account Enabled", "Yes" if profile.get("account_enabled") else "No")
    with col2:
        risk_level = risk.get("risk_level", "none")
        risk_icon = {"high": "🔴", "medium": "🟡", "low": "🟢", "none": "⚪"}.get(
            risk_level, "⚪"
        )
        st.metric("Risk Level", f"{risk_icon} {risk_level.upper()}")
        st.metric("Group Memberships", data.get("summary", {}).get("group_count", 0))

    groups = data.get("groups", [])
    if groups:
        with st.expander("Group Memberships"):
            for g in groups:
                st.markdown(f"- {g}")


def _save_enrichment_to_session(entity: str, data: dict) -> None:
    """Save enrichment result to the active investigation session."""
    session_id = st.session_state.get("active_session_id")
    if not session_id:
        return
    try:
        from app.investigation.session import SessionManager
        sm = SessionManager()
        sess = sm.load(session_id)
        if sess:
            sm.add_enrichment(sess, entity, data)
    except Exception:
        pass  # Silent fail — enrichment save is best-effort
