"""
Sentinel Investigator - Main Streamlit Application Entry Point
"""

from __future__ import annotations

import logging

import streamlit as st

# ── Page config (must be first Streamlit call) ────────────────────────────────
st.set_page_config(
    page_title="Sentinel Investigator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        "Get help": "https://github.com/pulkitrais/soc-agent",
        "Report a bug": "https://github.com/pulkitrais/soc-agent/issues",
        "About": "# Sentinel Investigator\nProduction-ready SOC investigation platform.",
    },
)

# ── Dark-mode CSS ─────────────────────────────────────────────────────────────
st.markdown(
    """
<style>
    /* Dark SOC-themed styles */
    .stApp { background-color: #0d1117; color: #e6edf3; }
    .stSidebar { background-color: #161b22; border-right: 1px solid #30363d; }
    .stTabs [data-baseweb="tab-list"] { background-color: #161b22; }
    .stTabs [data-baseweb="tab"] { color: #8b949e; }
    .stTabs [aria-selected="true"] { color: #58a6ff !important; }
    .stExpander { background-color: #161b22; border: 1px solid #30363d; border-radius: 0.5rem; }
    .stTextArea textarea { background-color: #0d1117; color: #e6edf3; font-family: 'Cascadia Code', monospace; }
    .stTextInput input { background-color: #161b22; color: #e6edf3; }
    .stSelectbox select { background-color: #161b22; color: #e6edf3; }
    code { color: #79c0ff !important; background-color: #010409 !important; }
    .stDataFrame { border: 1px solid #30363d !important; }
    div[data-testid="metric-container"] {
        background-color: #161b22;
        border: 1px solid #30363d;
        padding: 0.5rem 1rem;
        border-radius: 0.3rem;
    }
</style>
""",
    unsafe_allow_html=True,
)

# ── Imports ───────────────────────────────────────────────────────────────────
from app.ui.components.sidebar import render_sidebar
from app.ui.pages import home, query_lab, playbooks, threat_hunting, enrichment, investigation
from app.config import get_settings

# ── Logging ───────────────────────────────────────────────────────────────────
settings = get_settings()
logging.basicConfig(level=getattr(logging, settings.log_level, logging.INFO))
logger = logging.getLogger(__name__)

# ── Navigation ────────────────────────────────────────────────────────────────
PAGES = {
    "🏠 Home": home,
    "🔬 Query Lab": query_lab,
    "📋 Playbooks": playbooks,
    "🎯 Threat Hunting": threat_hunting,
    "🔎 Enrichment": enrichment,
    "🗒 Investigations": investigation,
}


def main() -> None:
    """Main application entry point."""
    # Render sidebar (returns selected workspace_id)
    render_sidebar()

    # Navigation in sidebar
    with st.sidebar:
        st.markdown("#### 📂 Navigation")
        page_name = st.radio(
            "Go to:",
            list(PAGES.keys()),
            key="navigation",
            label_visibility="collapsed",
        )

    # Render selected page
    PAGES[page_name].render()


if __name__ == "__main__":
    main()
