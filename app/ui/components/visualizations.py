"""
Visualisation helpers for Plotly-based charts used across the Streamlit UI.
"""

from __future__ import annotations

from typing import Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# Dark SOC-friendly colour palette
_BG = "#0d1117"
_SURFACE = "#161b22"
_ACCENT = "#58a6ff"
_TEXT = "#e6edf3"

_LAYOUT_BASE = {
    "paper_bgcolor": _BG,
    "plot_bgcolor": _SURFACE,
    "font": {"color": _TEXT, "family": "Segoe UI"},
    "margin": {"l": 40, "r": 20, "t": 50, "b": 40},
}


def timeline_chart(
    df: pd.DataFrame,
    time_col: str,
    count_col: Optional[str] = None,
    title: str = "Event Timeline",
    color_col: Optional[str] = None,
) -> go.Figure:
    """
    Build a timeline / area chart from a dataframe.

    Args:
        df: Source DataFrame.
        time_col: Column name for the time axis.
        count_col: Column to use for y-axis (optional; counts rows if None).
        title: Chart title.
        color_col: Column for colour grouping (optional).

    Returns:
        Plotly Figure.
    """
    if df is None or df.empty:
        return _empty_figure(title)

    df = df.copy()
    df[time_col] = pd.to_datetime(df[time_col], errors="coerce", utc=True)
    df = df.dropna(subset=[time_col])

    if count_col and count_col in df.columns:
        y = count_col
    else:
        # Bin events by hour and count
        df["__count__"] = 1
        y = "__count__"

    if color_col and color_col in df.columns:
        fig = px.bar(df, x=time_col, y=y, color=color_col, title=title)
    else:
        fig = px.bar(df, x=time_col, y=y, title=title, color_discrete_sequence=[_ACCENT])

    fig.update_layout(**_LAYOUT_BASE)
    return fig


def frequency_bar(
    series: pd.Series,
    title: str = "Frequency",
    top_n: int = 20,
    horizontal: bool = True,
) -> go.Figure:
    """Bar chart of top-N value counts from a pandas Series."""
    if series is None or series.empty:
        return _empty_figure(title)

    counts = series.value_counts().head(top_n).reset_index()
    counts.columns = ["value", "count"]

    if horizontal:
        fig = px.bar(
            counts, y="value", x="count", orientation="h",
            title=title, color_discrete_sequence=[_ACCENT],
        )
        fig.update_layout(yaxis={"categoryorder": "total ascending"})
    else:
        fig = px.bar(
            counts, x="value", y="count",
            title=title, color_discrete_sequence=[_ACCENT],
        )
    fig.update_layout(**_LAYOUT_BASE)
    return fig


def geo_map(
    df: pd.DataFrame,
    lat_col: str = "Latitude",
    lon_col: str = "Longitude",
    hover_col: str = "IPAddress",
    title: str = "IP Geolocation Map",
) -> go.Figure:
    """Scatter geo map of IP locations."""
    if df is None or df.empty or lat_col not in df.columns:
        return _empty_figure(title)

    fig = px.scatter_geo(
        df, lat=lat_col, lon=lon_col,
        hover_name=hover_col if hover_col in df.columns else None,
        title=title,
        color_discrete_sequence=[_ACCENT],
    )
    fig.update_layout(
        **_LAYOUT_BASE,
        geo={"bgcolor": _SURFACE, "lakecolor": _SURFACE, "showland": True, "landcolor": "#21262d"},
    )
    return fig


def risk_gauge(score: int, title: str = "Risk Score") -> go.Figure:
    """Gauge chart for a 0-100 risk score."""
    color = (
        "#ff4444" if score >= 75
        else "#ff8800" if score >= 50
        else "#ffcc00" if score >= 25
        else "#44bb44"
    )
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            title={"text": title, "font": {"color": _TEXT}},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": color},
                "bgcolor": _SURFACE,
                "bordercolor": "#30363d",
                "steps": [
                    {"range": [0, 25], "color": "#1a3a1a"},
                    {"range": [25, 50], "color": "#3a3a00"},
                    {"range": [50, 75], "color": "#3a1a00"},
                    {"range": [75, 100], "color": "#3a0000"},
                ],
            },
            number={"font": {"color": color}},
        )
    )
    fig.update_layout(**_LAYOUT_BASE, height=250)
    return fig


def _empty_figure(title: str) -> go.Figure:
    """Return an empty placeholder figure."""
    fig = go.Figure()
    fig.update_layout(
        **_LAYOUT_BASE,
        title=title,
        annotations=[{
            "text": "No data available",
            "x": 0.5, "y": 0.5,
            "xref": "paper", "yref": "paper",
            "showarrow": False,
            "font": {"color": "#8b949e"},
        }],
    )
    return fig
