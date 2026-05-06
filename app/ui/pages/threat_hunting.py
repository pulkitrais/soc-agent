"""
Threat Hunting page - MITRE ATT&CK mapped hunting templates.
"""

from __future__ import annotations

from datetime import timedelta

import streamlit as st

from app.hunting.templates import HUNTING_TEMPLATES, get_all_tactics, get_templates_by_tactic
from app.sentinel.client import SentinelClient
from app.ui.components.visualizations import frequency_bar, timeline_chart


def render() -> None:
    """Render the Threat Hunting page."""
    st.markdown("## 🎯 Threat Hunting")
    st.markdown(
        "MITRE ATT&CK mapped hunting templates. Run pre-built hunts or customise them."
    )
    st.divider()

    workspace_id = st.session_state.get("workspace_id", "")

    # ── Filter controls ───────────────────────────────────────────────────────
    col1, col2, col3 = st.columns(3)
    with col1:
        tactics = ["All Tactics"] + get_all_tactics()
        selected_tactic = st.selectbox("Filter by tactic:", tactics, key="hunt_tactic")
    with col2:
        severity_opts = ["All", "critical", "high", "medium", "low"]
        selected_severity = st.selectbox("Filter by severity:", severity_opts, key="hunt_severity")
    with col3:
        timerange_opts = {
            "Last 1 hour": timedelta(hours=1),
            "Last 24 hours": timedelta(days=1),
            "Last 7 days": timedelta(days=7),
        }
        selected_range = st.selectbox("Time range:", list(timerange_opts.keys()), key="hunt_range")
        timespan = timerange_opts[selected_range]

    # ── Filter templates ──────────────────────────────────────────────────────
    templates = HUNTING_TEMPLATES
    if selected_tactic != "All Tactics":
        templates = [t for t in templates if selected_tactic in t.mitre_tactic]
    if selected_severity != "All":
        templates = [t for t in templates if t.severity == selected_severity]

    st.markdown(f"**{len(templates)} hunting template(s) available**")
    st.divider()

    for template in templates:
        severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
            template.severity, "⚪"
        )
        data_sources_str = ", ".join(template.data_sources)

        with st.expander(
            f"{severity_icon} **{template.name}** — `{template.mitre_technique_id}`"
        ):
            col1, col2 = st.columns([2, 1])
            with col1:
                st.markdown(template.description)
                if template.tags:
                    st.markdown("Tags: " + " ".join(f"`{t}`" for t in template.tags))
            with col2:
                st.markdown(f"**Tactic:** {template.mitre_tactic}")
                st.markdown(f"**Technique:** {template.mitre_technique}")
                st.markdown(f"**Data sources:** `{data_sources_str}`")

            kql_key = f"hunt_kql_{template.id}"
            kql = st.text_area(
                "KQL (editable):",
                value=template.kql,
                height=150,
                key=kql_key,
            )

            col_a, col_b, col_c = st.columns(3)
            with col_a:
                if st.button(f"▶ Run Hunt", key=f"run_{template.id}", use_container_width=True):
                    if not workspace_id:
                        st.error("Configure a workspace first.")
                    else:
                        with st.spinner("Running hunt…"):
                            client = SentinelClient(workspace_id)
                            result = client.run_query(kql, timespan=timespan)

                        if not result.success:
                            st.error(f"Hunt failed: {result.error}")
                        else:
                            findings = result.row_count > 0
                            if findings:
                                st.error(f"🚨 {result.row_count} findings — investigate!")
                            else:
                                st.success("✅ No hits — clean for this time range")
                            st.session_state[f"hunt_result_{template.id}"] = result

                            if st.session_state.get("active_session_id"):
                                from app.investigation.session import SessionManager
                                sm = SessionManager()
                                sess = sm.load(st.session_state["active_session_id"])
                                if sess:
                                    sm.add_query_result(
                                        sess, f"Hunt: {template.name}", kql,
                                        result.dataframe, result.row_count,
                                    )

            with col_b:
                if st.button("💾 Save to Library", key=f"save_{template.id}", use_container_width=True):
                    from app.kql.library import QueryLibrary, SavedQuery
                    lib = QueryLibrary()
                    lib.save(SavedQuery(
                        name=template.name,
                        description=template.description,
                        kql=kql,
                        tags=template.tags + ["hunting", template.mitre_technique_id],
                        category="hunting",
                    ))
                    st.success("Saved!")

            with col_c:
                mitre_url = f"https://attack.mitre.org/techniques/{template.mitre_technique_id.replace('.', '/')}/"
                st.link_button("🔗 MITRE ATT&CK", mitre_url, use_container_width=True)

            # Show results
            result_key = f"hunt_result_{template.id}"
            if result_key in st.session_state:
                res = st.session_state[result_key]
                df = res.dataframe
                if df is not None and not df.empty:
                    st.dataframe(df, use_container_width=True, height=300)

                    # Timeline if there's a time column
                    time_cols = [c for c in df.columns if "time" in c.lower()]
                    if time_cols:
                        fig = timeline_chart(df, time_cols[0], title=f"{template.name} – Timeline")
                        st.plotly_chart(fig, use_container_width=True)
