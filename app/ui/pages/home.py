"""
Home / Dashboard page
"""

from __future__ import annotations

import streamlit as st

from app.config import get_settings


def render() -> None:
    """Render the home/dashboard page."""
    settings = get_settings()

    st.markdown(
        """
        <h1 style="color:#58a6ff;">🛡️ Sentinel Investigator</h1>
        <p style="color:#8b949e;font-size:1.1rem;">
        Production-ready SOC investigation platform for Microsoft Sentinel
        </p>
        """,
        unsafe_allow_html=True,
    )

    st.divider()

    # ── Feature cards ─────────────────────────────────────────────────────────
    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown(
            """
            <div style="background:#161b22;border:1px solid #30363d;border-radius:.5rem;padding:1.2rem;">
            <h3 style="color:#58a6ff;">🔬 Query Lab</h3>
            <p>Natural language → KQL conversion. Run queries, validate before execution,
            save to your personal library.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            """
            <div style="background:#161b22;border:1px solid #30363d;border-radius:.5rem;padding:1.2rem;">
            <h3 style="color:#58a6ff;">📋 Playbooks</h3>
            <p>7 pre-built investigation playbooks (Suspicious Sign-ins, Malware, Phishing,
            Lateral Movement, C2, Privilege Escalation, Data Exfiltration).</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col3:
        st.markdown(
            """
            <div style="background:#161b22;border:1px solid #30363d;border-radius:.5rem;padding:1.2rem;">
            <h3 style="color:#58a6ff;">🎯 Threat Hunting</h3>
            <p>MITRE ATT&CK mapped hunting templates across all tactics from
            Reconnaissance to Impact.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<br>", unsafe_allow_html=True)
    col4, col5, col6 = st.columns(3)

    with col4:
        st.markdown(
            """
            <div style="background:#161b22;border:1px solid #30363d;border-radius:.5rem;padding:1.2rem;">
            <h3 style="color:#58a6ff;">🔎 Enrichment</h3>
            <p>One-click entity enrichment for IPs (VirusTotal + AbuseIPDB),
            file hashes, and users (Microsoft Graph).</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col5:
        st.markdown(
            """
            <div style="background:#161b22;border:1px solid #30363d;border-radius:.5rem;padding:1.2rem;">
            <h3 style="color:#58a6ff;">🗒 Investigations</h3>
            <p>Session-based investigation tracker with timeline, evidence collection,
            and entity tracking.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col6:
        st.markdown(
            """
            <div style="background:#161b22;border:1px solid #30363d;border-radius:.5rem;padding:1.2rem;">
            <h3 style="color:#58a6ff;">📄 Reports</h3>
            <p>Export investigation findings to Word, Excel, or self-contained
            HTML incident reports.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.divider()

    # ── Quick start ───────────────────────────────────────────────────────────
    st.markdown("### 🚀 Quick Start")
    with st.expander("Getting started in 3 steps"):
        st.markdown("""
1. **Configure Azure auth** — Copy `.env.example` to `.env` and set your credentials,
   then select your auth method in the sidebar.
2. **Select a workspace** — Add your Sentinel workspace ID in the sidebar
   (or set `SENTINEL_WORKSPACE_ID` in `.env`).
3. **Start investigating** — Use the **Query Lab** for ad-hoc queries,
   pick a **Playbook** for guided investigation, or run a **Threat Hunt**.
        """)

    st.markdown("### 🔧 Current Configuration")
    col_a, col_b = st.columns(2)
    with col_a:
        st.metric("Auth Method", settings.azure_auth_method)
        st.metric("OpenAI Model", settings.openai_model)
    with col_b:
        openai_ready = "✅ Configured" if settings.openai_api_key else "⚠️ Not set"
        vt_ready = "✅ Configured" if settings.virustotal_api_key else "⚠️ Not set"
        st.metric("OpenAI API", openai_ready)
        st.metric("VirusTotal API", vt_ready)
