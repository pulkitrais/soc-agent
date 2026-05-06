"""
Investigation Session page
Create and manage investigation sessions, timeline, evidence, and exports.
"""

from __future__ import annotations

import json

import streamlit as st

from app.investigation.session import SessionManager, InvestigationSession
from app.reporting.exporter import ReportExporter


def render() -> None:
    """Render the Investigation Sessions page."""
    st.markdown("## 🗒 Investigations")
    st.markdown("Track your investigation sessions, collect evidence, and export findings.")
    st.divider()

    sm = SessionManager()
    tabs = st.tabs(["📋 All Sessions", "🔍 Active Session", "📄 Export"])

    # ── All Sessions ──────────────────────────────────────────────────────────
    with tabs[0]:
        st.markdown("### All Investigation Sessions")

        col1, col2 = st.columns([3, 1])
        with col1:
            pass
        with col2:
            if st.button("➕ New Session", use_container_width=True, type="primary"):
                st.session_state["show_new_session_form"] = True

        if st.session_state.get("show_new_session_form"):
            with st.form("new_session_form"):
                title = st.text_input("Title", placeholder="e.g. Suspicious sign-in for user X")
                description = st.text_area("Description", height=80)
                severity = st.selectbox("Severity", ["low", "medium", "high", "critical"])
                analyst = st.text_input("Analyst", value="analyst")
                submitted = st.form_submit_button("Create Session")
                if submitted:
                    sess = sm.create(
                        title=title or "New Investigation",
                        description=description,
                        severity=severity,
                        analyst=analyst,
                    )
                    st.session_state["active_session_id"] = sess.id
                    st.session_state["show_new_session_form"] = False
                    st.success(f"Created session: {sess.title}")
                    st.rerun()

        sessions = sm.list_sessions()
        if not sessions:
            st.info("No sessions yet. Create one to start tracking your investigation.")
        else:
            for s in sessions:
                sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
                    s["severity"], "⚪"
                )
                status_icon = {"open": "🔓", "in_progress": "🔄", "closed": "✅", "escalated": "🚨"}.get(
                    s["status"], "❓"
                )
                is_active = s["id"] == st.session_state.get("active_session_id")
                label = f"{'⭐ ACTIVE — ' if is_active else ''}{sev_icon} {s['title']} — {status_icon} {s['status'].upper()}"

                with st.expander(label):
                    st.markdown(f"**ID:** `{s['id']}`")
                    st.markdown(f"**Analyst:** {s['analyst']} | **Evidence items:** {s['evidence_count']}")
                    st.markdown(f"**Created:** {s['created_at'][:19]}")

                    col_a, col_b, col_c = st.columns(3)
                    with col_a:
                        if st.button("📂 Open", key=f"open_{s['id']}", use_container_width=True):
                            st.session_state["active_session_id"] = s["id"]
                            st.rerun()
                    with col_b:
                        if st.button("🗑 Delete", key=f"del_{s['id']}", use_container_width=True):
                            sm.delete(s["id"])
                            if st.session_state.get("active_session_id") == s["id"]:
                                st.session_state["active_session_id"] = None
                            st.rerun()

    # ── Active Session ────────────────────────────────────────────────────────
    with tabs[1]:
        session_id = st.session_state.get("active_session_id")
        if not session_id:
            st.info("No active session. Create or open one from the 'All Sessions' tab.")
            return

        session = sm.load(session_id)
        if not session:
            st.error(f"Could not load session {session_id}")
            return

        # Header
        col1, col2 = st.columns([3, 1])
        with col1:
            new_title = st.text_input("Title", value=session.title, key="sess_title")
            if new_title != session.title:
                session.title = new_title
                sm.save(session)
        with col2:
            sev = st.selectbox(
                "Severity", ["low", "medium", "high", "critical"],
                index=["low", "medium", "high", "critical"].index(session.severity),
                key="sess_severity",
            )
            status = st.selectbox(
                "Status", ["open", "in_progress", "closed", "escalated"],
                index=["open", "in_progress", "closed", "escalated"].index(session.status),
                key="sess_status",
            )
            if sev != session.severity or status != session.status:
                session.severity = sev
                session.status = status
                sm.save(session)

        st.divider()

        # Notes
        st.markdown("#### 📝 Notes")
        notes = st.text_area("Investigation notes:", value=session.notes, height=150, key="sess_notes")
        if notes != session.notes:
            session.notes = notes
            sm.save(session)

        col_a, col_b = st.columns(2)
        with col_a:
            note_text = st.text_input("Quick note:", key="quick_note")
        with col_b:
            if st.button("➕ Add Note", use_container_width=True, key="add_note"):
                if note_text:
                    sm.add_note(session, note_text)
                    st.rerun()

        # Entities
        st.divider()
        st.markdown("#### 🏷 Tracked Entities")
        col1, col2, col3 = st.columns(3)
        with col1:
            entity_type = st.selectbox("Entity type:", ["ip", "user", "hash", "device", "domain"], key="ent_type")
        with col2:
            entity_value = st.text_input("Value:", key="ent_value")
        with col3:
            if st.button("➕ Add Entity", use_container_width=True, key="add_entity"):
                if entity_value:
                    sm.add_entity(session, entity_type, entity_value)
                    st.rerun()

        if session.entities:
            for etype, values in session.entities.items():
                st.markdown(f"**{etype}:** " + " | ".join(f"`{v}`" for v in values))

        # Evidence
        st.divider()
        st.markdown(f"#### 📁 Evidence ({len(session.evidence)} items)")
        for i, ev in enumerate(reversed(session.evidence)):
            type_icon = {"note": "📝", "query_result": "🗄", "enrichment": "🔎", "alert": "🚨"}.get(
                ev.item_type, "📌"
            )
            with st.expander(f"{type_icon} {ev.title} — {ev.timestamp[:19]}"):
                if ev.content:
                    st.code(ev.content[:1000], language="sql" if ev.item_type == "query_result" else "text")
                if ev.data.get("preview"):
                    import pandas as pd
                    df = pd.DataFrame(ev.data["preview"])
                    st.dataframe(df, use_container_width=True, height=200)

        # Timeline
        st.divider()
        st.markdown(f"#### ⏱ Timeline ({len(session.timeline)} events)")
        for event in reversed(session.timeline[-20:]):
            st.markdown(f"- `{event.get('timestamp', '')[:19]}` — {event.get('event', '')}")

    # ── Export ────────────────────────────────────────────────────────────────
    with tabs[2]:
        session_id = st.session_state.get("active_session_id")
        if not session_id:
            st.info("No active session to export.")
            return

        session = sm.load(session_id)
        if not session:
            st.error("Could not load session.")
            return

        st.markdown(f"### Export: {session.title}")
        exporter = ReportExporter()

        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("📄 HTML Report", use_container_width=True, type="primary"):
                with st.spinner("Generating HTML report…"):
                    path = exporter.export_html(session)
                st.success(f"Report saved: {path}")
                with open(path, "rb") as f:
                    st.download_button("⬇ Download HTML", f, file_name=path.name, mime="text/html")

        with col2:
            if st.button("📊 Excel Report", use_container_width=True):
                with st.spinner("Generating Excel report…"):
                    try:
                        path = exporter.export_excel(session)
                        st.success(f"Report saved: {path}")
                        with open(path, "rb") as f:
                            st.download_button(
                                "⬇ Download Excel", f, file_name=path.name,
                                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            )
                    except RuntimeError as exc:
                        st.error(str(exc))

        with col3:
            if st.button("📝 Word Report", use_container_width=True):
                with st.spinner("Generating Word report…"):
                    try:
                        path = exporter.export_word(session)
                        st.success(f"Report saved: {path}")
                        with open(path, "rb") as f:
                            st.download_button(
                                "⬇ Download Word", f, file_name=path.name,
                                mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            )
                    except RuntimeError as exc:
                        st.error(str(exc))
