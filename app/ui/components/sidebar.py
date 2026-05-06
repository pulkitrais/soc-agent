"""
Streamlit sidebar component - workspace selector, session management, navigation.
"""

from __future__ import annotations

import streamlit as st

from app.config import get_settings
from app.sentinel.workspace import WorkspaceManager, WorkspaceConfig


def render_sidebar() -> str | None:
    """
    Render the application sidebar.
    Returns the currently selected workspace_id (or None).
    """
    settings = get_settings()

    with st.sidebar:
        st.image("https://img.shields.io/badge/Sentinel-Investigator-blue?style=for-the-badge&logo=microsoft-azure")
        st.markdown("### 🔍 Sentinel Investigator")
        st.markdown(f"*v{settings.app_version}*")
        st.divider()

        # ── Workspace selector ────────────────────────────────────────────────
        st.markdown("#### 🗂 Workspace")
        mgr = WorkspaceManager()
        workspaces = mgr.list_workspaces()

        if workspaces:
            ws_names = [f"{w.name} ({w.workspace_id[:8]}...)" for w in workspaces]
            selected_name = st.selectbox("Select workspace", ws_names, key="workspace_selector")
            idx = ws_names.index(selected_name)
            selected_ws = workspaces[idx]
            st.session_state["workspace_id"] = selected_ws.workspace_id
        else:
            default = mgr.get_default()
            if default:
                st.info(f"Using: {default.name}")
                st.session_state["workspace_id"] = default.workspace_id
            else:
                st.warning("No workspace configured.")
                ws_id = st.text_input(
                    "Workspace ID",
                    placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                    key="manual_workspace_id",
                )
                if ws_id:
                    st.session_state["workspace_id"] = ws_id

        st.divider()

        # ── Active investigation session ──────────────────────────────────────
        st.markdown("#### 🗒 Investigation Session")
        if "active_session_id" in st.session_state and st.session_state["active_session_id"]:
            sid = st.session_state["active_session_id"]
            st.success(f"Active: `{sid[:8]}...`")
            if st.button("📋 Clear session"):
                st.session_state["active_session_id"] = None
                st.rerun()
        else:
            st.info("No active session")

        st.divider()

        # ── Auth status ───────────────────────────────────────────────────────
        st.markdown("#### 🔐 Auth")
        auth_method = settings.azure_auth_method
        st.markdown(f"Method: `{auth_method}`")

        if st.button("Test Connection", use_container_width=True):
            with st.spinner("Testing Azure connection…"):
                try:
                    from app.auth.azure_auth import get_auth_manager
                    ok = get_auth_manager().test_credential()
                    if ok:
                        st.success("✅ Connected")
                    else:
                        st.error("❌ Auth failed")
                except Exception as exc:
                    st.error(f"Error: {exc}")

        st.divider()

        # ── Help links ────────────────────────────────────────────────────────
        with st.expander("ℹ Help"):
            st.markdown(
                "**Docs**: [README](https://github.com/pulkitrais/soc-agent/blob/main/README.md)\n\n"
                "**MITRE**: [ATT&CK](https://attack.mitre.org/)\n\n"
                "**KQL ref**: [docs.microsoft.com](https://docs.microsoft.com/azure/data-explorer/kusto/query/)"
            )

    return st.session_state.get("workspace_id")
