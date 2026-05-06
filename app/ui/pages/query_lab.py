"""
Query Lab page
Natural language → KQL, query validation, execution, and result visualisation.
"""

from __future__ import annotations

from datetime import timedelta

import pandas as pd
import streamlit as st

from app.kql.generator import generate_kql
from app.kql.validator import validate_kql
from app.kql.library import QueryLibrary, SavedQuery
from app.sentinel.client import SentinelClient
from app.ui.components.visualizations import timeline_chart, frequency_bar


def render() -> None:
    """Render the Query Lab page."""
    st.markdown("## 🔬 Query Lab")
    st.markdown("Natural language to KQL conversion, query validation, and execution.")
    st.divider()

    workspace_id = st.session_state.get("workspace_id", "")
    library = QueryLibrary()

    tabs = st.tabs(["✨ NL → KQL", "📚 Query Library", "🗄 Run Query"])

    # ── Tab 1: NL → KQL ──────────────────────────────────────────────────────
    with tabs[0]:
        st.markdown("### Natural Language to KQL")
        nl_input = st.text_area(
            "Describe what you want to find:",
            placeholder='e.g. "Show me all failed logons for user johndoe in the last 24 hours"',
            height=100,
            key="nl_input",
        )
        context = st.text_input(
            "Optional context (entity names, previous findings):",
            key="nl_context",
        )

        if st.button("⚡ Generate KQL", use_container_width=True, type="primary"):
            if not nl_input.strip():
                st.warning("Please enter a query description.")
            else:
                with st.spinner("Generating KQL…"):
                    result = generate_kql(nl_input.strip(), context=context or None)
                st.session_state["generated_kql"] = result["kql"]
                source_badge = "🤖 OpenAI" if result["source"] == "openai" else "⚙️ Template"
                st.success(f"Query generated ({source_badge})")

        if "generated_kql" in st.session_state:
            generated = st.session_state["generated_kql"]
            kql_edit = st.text_area(
                "Generated KQL (editable):",
                value=generated,
                height=200,
                key="kql_edit",
            )

            # Validate
            validation = validate_kql(kql_edit)
            if validation.errors:
                for err in validation.errors:
                    st.error(f"❌ {err}")
            if validation.warnings:
                for warn in validation.warnings:
                    st.warning(f"⚠️ {warn}")
            if validation.suggestions:
                for sug in validation.suggestions:
                    st.info(f"💡 {sug}")

            col1, col2 = st.columns(2)
            with col1:
                if st.button("▶ Run in Query Lab", use_container_width=True):
                    st.session_state["run_query_kql"] = kql_edit
                    st.session_state["active_tab"] = "run"
                    st.rerun()
            with col2:
                with st.popover("💾 Save to Library"):
                    save_name = st.text_input("Query name", key="save_name")
                    save_desc = st.text_input("Description", key="save_desc")
                    save_tags = st.text_input("Tags (comma-separated)", key="save_tags")
                    if st.button("Save", key="do_save"):
                        tags = [t.strip() for t in save_tags.split(",") if t.strip()]
                        q = SavedQuery(
                            name=save_name or "Untitled",
                            description=save_desc,
                            kql=kql_edit,
                            tags=tags,
                        )
                        library.save(q)
                        st.success(f"Saved: {q.name}")

    # ── Tab 2: Query Library ──────────────────────────────────────────────────
    with tabs[1]:
        st.markdown("### 📚 Saved Query Library")
        search_term = st.text_input("🔍 Search queries", key="lib_search")
        queries = library.search(search_term) if search_term else library.list_all()

        if not queries:
            st.info("No queries found.")
        else:
            for q in queries:
                with st.expander(f"**{q.name}** — {q.category}"):
                    if q.description:
                        st.markdown(f"*{q.description}*")
                    if q.tags:
                        st.markdown(" ".join(f"`{t}`" for t in q.tags))
                    st.code(q.kql, language="sql")
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.button(f"▶ Run", key=f"run_{q.id}"):
                            st.session_state["run_query_kql"] = q.kql
                    with col2:
                        if not q.id.startswith("builtin-"):
                            if st.button(f"🗑 Delete", key=f"del_{q.id}"):
                                library.delete(q.id)
                                st.rerun()

    # ── Tab 3: Run Query ──────────────────────────────────────────────────────
    with tabs[2]:
        st.markdown("### 🗄 Execute Query")

        if not workspace_id:
            st.warning("⚠️ No workspace configured. Set a workspace in the sidebar.")
            return

        # Time range
        col1, col2 = st.columns(2)
        with col1:
            timerange_options = {
                "Last 1 hour": timedelta(hours=1),
                "Last 6 hours": timedelta(hours=6),
                "Last 24 hours": timedelta(days=1),
                "Last 3 days": timedelta(days=3),
                "Last 7 days": timedelta(days=7),
                "Last 30 days": timedelta(days=30),
            }
            selected_range = st.selectbox("Time range", list(timerange_options.keys()))
            timespan = timerange_options[selected_range]

        run_kql = st.session_state.pop("run_query_kql", "")

        kql_to_run = st.text_area(
            "KQL Query:",
            value=run_kql,
            height=200,
            key="kql_to_run",
            placeholder="Enter your KQL query here…",
        )

        # Cost estimate
        if kql_to_run:
            estimate = SentinelClient(workspace_id).estimate_query_cost(kql_to_run)
            level_color = {"low": "green", "medium": "orange", "high": "red"}.get(
                estimate["level"], "gray"
            )
            st.markdown(
                f"**Cost estimate:** :{level_color}[{estimate['level'].upper()}]"
            )
            for w in estimate.get("warnings", []):
                st.caption(f"⚠️ {w}")

        if st.button("▶ Run Query", use_container_width=True, type="primary", key="execute_query"):
            if not kql_to_run.strip():
                st.warning("Please enter a KQL query.")
            else:
                validation = validate_kql(kql_to_run)
                if not validation.is_valid:
                    for err in validation.errors:
                        st.error(f"Validation error: {err}")
                    return

                with st.spinner("Running query…"):
                    client = SentinelClient(workspace_id)
                    result = client.run_query(kql_to_run, timespan=timespan)

                if not result.success:
                    st.error(f"Query failed: {result.error}")
                    return

                st.success(f"✅ {result.row_count} rows returned")
                df = result.dataframe

                # Save to active session
                if st.session_state.get("active_session_id"):
                    from app.investigation.session import SessionManager
                    sm = SessionManager()
                    sess = sm.load(st.session_state["active_session_id"])
                    if sess:
                        sm.add_query_result(sess, "Ad-hoc query", kql_to_run, df, result.row_count)

                # Display data
                st.dataframe(df, use_container_width=True, height=400)

                # Visualise
                if not df.empty:
                    st.markdown("#### 📊 Visualisations")
                    time_cols = [c for c in df.columns if "time" in c.lower() or "timestamp" in c.lower()]
                    if time_cols:
                        fig = timeline_chart(df, time_cols[0], title="Events Over Time")
                        st.plotly_chart(fig, use_container_width=True)

                    cat_cols = [c for c in df.columns if df[c].dtype == object]
                    if cat_cols:
                        sel_col = st.selectbox("Frequency chart column:", cat_cols, key="freq_col")
                        fig2 = frequency_bar(df[sel_col], title=f"Top {sel_col} values")
                        st.plotly_chart(fig2, use_container_width=True)

                # Download
                csv_data = df.to_csv(index=False).encode("utf-8")
                st.download_button(
                    "⬇ Download CSV",
                    data=csv_data,
                    file_name="query_results.csv",
                    mime="text/csv",
                )
