"""
Sentinel / Log Analytics Query Client
Wraps azure-monitor-query LogsQueryClient for running KQL against workspaces.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Optional

import pandas as pd
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from azure.monitor.query import LogsQueryResult, LogsTable

from app.auth.azure_auth import get_auth_manager, AZURE_MONITOR_SCOPE
from app.config import get_settings

logger = logging.getLogger(__name__)


@dataclass
class QueryResult:
    """Normalised result from a Log Analytics query."""

    success: bool
    dataframe: Optional[pd.DataFrame] = None
    error: Optional[str] = None
    statistics: dict[str, Any] = field(default_factory=dict)
    visualization: Optional[str] = None
    row_count: int = 0
    columns: list[str] = field(default_factory=list)


class SentinelClient:
    """
    Thin wrapper around LogsQueryClient.
    Provides query execution, workspace validation, and basic cost hinting.
    """

    def __init__(
        self,
        workspace_id: Optional[str] = None,
    ) -> None:
        self._settings = get_settings()
        self._workspace_id = workspace_id or self._settings.sentinel_workspace_id
        self._logs_client: Optional[LogsQueryClient] = None

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def workspace_id(self) -> str:
        return self._workspace_id

    @workspace_id.setter
    def workspace_id(self, value: str) -> None:
        self._workspace_id = value
        # Force client re-creation on workspace change
        self._logs_client = None

    # ── Client lifecycle ──────────────────────────────────────────────────────

    def _get_logs_client(self) -> LogsQueryClient:
        if self._logs_client is None:
            credential = get_auth_manager().get_credential()
            self._logs_client = LogsQueryClient(credential)
        return self._logs_client

    # ── Public API ────────────────────────────────────────────────────────────

    def run_query(
        self,
        kql: str,
        timespan: timedelta = timedelta(days=1),
        server_timeout: int = 180,
    ) -> QueryResult:
        """
        Execute a KQL query against the configured workspace.

        Args:
            kql: Kusto Query Language string.
            timespan: Time range for the query (default 24 h).
            server_timeout: Maximum seconds to wait for query response.

        Returns:
            QueryResult with dataframe or error information.
        """
        if not self._workspace_id:
            return QueryResult(
                success=False,
                error="No workspace_id configured. Set SENTINEL_WORKSPACE_ID or select a workspace in the UI.",
            )

        try:
            client = self._get_logs_client()
            logger.debug("Running KQL query on workspace %s", self._workspace_id)

            response = client.query_workspace(
                workspace_id=self._workspace_id,
                query=kql,
                timespan=timespan,
                server_timeout=server_timeout,
            )

            if response.status == LogsQueryStatus.SUCCESS:
                df = self._tables_to_dataframe(response.tables)
                return QueryResult(
                    success=True,
                    dataframe=df,
                    row_count=len(df),
                    columns=list(df.columns),
                    statistics=response.statistics or {},
                )
            else:
                # Partial failure
                partial_data = response.partial_data
                error_msg = str(response.partial_error) if response.partial_error else "Partial query failure"
                df = self._tables_to_dataframe(partial_data) if partial_data else pd.DataFrame()
                return QueryResult(
                    success=False,
                    dataframe=df,
                    error=error_msg,
                    row_count=len(df),
                    columns=list(df.columns),
                )

        except Exception as exc:
            logger.error("Query execution failed: %s", exc)
            return QueryResult(success=False, error=str(exc))

    def estimate_query_cost(self, kql: str) -> dict[str, Any]:
        """
        Provide a rough cost / complexity estimate without running the query.
        Checks for expensive operations like cross-workspace joins or large scans.
        """
        warnings = []
        score = 0

        kql_lower = kql.lower()

        # Heavy table scans
        heavy_tables = ["securityevent", "commonsecuritylog", "syslog", "signinlogs"]
        for tbl in heavy_tables:
            if tbl in kql_lower:
                score += 2
                warnings.append(f"Scans high-volume table: {tbl}")

        # Missing time filter
        if "ago(" not in kql_lower and "between(" not in kql_lower:
            score += 3
            warnings.append("No explicit time filter detected — may scan all history")

        # Cross-workspace joins
        if "workspace(" in kql_lower:
            score += 2
            warnings.append("Cross-workspace query detected")

        # join / union
        if "join" in kql_lower:
            score += 1
            warnings.append("JOIN detected — can be expensive on large datasets")
        if "union" in kql_lower:
            score += 1

        level = "low" if score <= 2 else ("medium" if score <= 5 else "high")
        return {
            "score": score,
            "level": level,
            "warnings": warnings,
        }

    def test_connection(self) -> bool:
        """Run a lightweight query to confirm workspace connectivity."""
        result = self.run_query(
            "search * | take 1",
            timespan=timedelta(minutes=5),
            server_timeout=30,
        )
        return result.success

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _tables_to_dataframe(tables: list[LogsTable]) -> pd.DataFrame:
        """Flatten query result tables into a single pandas DataFrame."""
        if not tables:
            return pd.DataFrame()

        frames = []
        for table in tables:
            if table.rows:
                col_names = [col.name for col in table.columns]
                frames.append(pd.DataFrame(table.rows, columns=col_names))

        if not frames:
            return pd.DataFrame()

        return pd.concat(frames, ignore_index=True)
