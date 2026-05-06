"""
Investigation Playbooks page
"""

from __future__ import annotations

from datetime import timedelta

import streamlit as st

from app.playbooks import PLAYBOOK_REGISTRY, get_playbook
from app.sentinel.client import SentinelClient
from app.ui.components.visualizations import timeline_chart, frequency_bar


def render() -> None:
    """Render the Playbooks page."""
    st.markdown("## 📋 Investigation Playbooks")
    st.markdown(
        "Pre-built investigation workflows for common security scenarios. "
        "Each playbook contains multiple KQL steps."
    )
    st.divider()

    workspace_id = st.session_state.get("workspace_id", "")

    # ── Playbook selector ─────────────────────────────────────────────────────
    playbook_names = list(PLAYBOOK_REGISTRY.keys())
    selected_name = st.selectbox(
        "Select Playbook:",
        playbook_names,
        key="playbook_select",
    )

    playbook = get_playbook(selected_name)

    # ── Playbook metadata ─────────────────────────────────────────────────────
    col1, col2 = st.columns([3, 1])
    with col1:
        st.markdown(f"**{playbook.name}**")
        st.caption(playbook.description)
    with col2:
        st.markdown(f"**Tactic:** `{playbook.mitre_tactic}`")
        st.markdown(f"**Category:** `{playbook.category}`")

    st.divider()

    # ── Time range ────────────────────────────────────────────────────────────
    timerange_opts = {
        "Last 24 hours": timedelta(days=1),
        "Last 3 days": timedelta(days=3),
        "Last 7 days": timedelta(days=7),
    }
    col1, col2 = st.columns(2)
    with col1:
        selected_range = st.selectbox("Time range:", list(timerange_opts.keys()), key="pb_timerange")
        timespan = timerange_opts[selected_range]
    with col2:
        if not workspace_id:
            st.warning("No workspace configured")
        else:
            st.success(f"Workspace: `{workspace_id[:16]}…`")

    # ── Steps ─────────────────────────────────────────────────────────────────
    for i, step in enumerate(playbook.get_steps()):
        severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
            step.severity, "⚪"
        )

        with st.expander(
            f"{severity_icon} {step.title}",
            expanded=(i == 0),
        ):
            col_a, col_b = st.columns([3, 1])
            with col_a:
                st.caption(step.description)
            with col_b:
                if step.mitre_technique:
                    st.markdown(f"🔖 `{step.mitre_technique}`")

            kql_key = f"pb_kql_{i}"
            kql = st.text_area(
                "KQL (editable):",
                value=step.kql,
                height=150,
                key=kql_key,
            )

            col1, col2 = st.columns(2)
            with col1:
                run_key = f"pb_run_{i}"
                if st.button(f"▶ Run Step", key=run_key, use_container_width=True):
                    if not workspace_id:
                        st.error("Configure a workspace first.")
                    else:
                        with st.spinner("Running query…"):
                            client = SentinelClient(workspace_id)
                            result = client.run_query(kql, timespan=timespan)

                        if not result.success:
                            st.error(f"Query failed: {result.error}")
                        else:
                            st.success(f"✅ {result.row_count} rows")
                            st.session_state[f"pb_result_{i}"] = result

                            # Save to session
                            if st.session_state.get("active_session_id"):
                                from app.investigation.session import SessionManager
                                sm = SessionManager()
                                sess = sm.load(st.session_state["active_session_id"])
                                if sess:
                                    sm.add_query_result(
                                        sess, step.title, kql,
                                        result.dataframe, result.row_count,
                                    )
            with col2:
                if st.button("💾 Save KQL", key=f"pb_save_{i}", use_container_width=True):
                    from app.kql.library import QueryLibrary, SavedQuery
                    lib = QueryLibrary()
                    lib.save(SavedQuery(
                        name=f"{playbook.name}: {step.title}",
                        description=step.description,
                        kql=kql,
                        tags=[playbook.category, "playbook"],
                        category="playbook",
                    ))
                    st.success("Saved to library!")

            # Show results if they exist
            result_key = f"pb_result_{i}"
            if result_key in st.session_state:
                res = st.session_state[result_key]
                df = res.dataframe
                if df is not None and not df.empty:
                    st.dataframe(df, use_container_width=True, height=300)
                    time_cols = [c for c in df.columns if "time" in c.lower()]
                    if time_cols:
                        fig = timeline_chart(df, time_cols[0], title=f"{step.title} – Timeline")
                        st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No results returned for this step.")
