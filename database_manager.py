"""
database_manager.py

SQLite persistence layer for RBVM CVE ingestion.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Optional


@dataclass(frozen=True)
class CVERecord:
    """Represents a normalized CVE record for persistence."""

    cve_id: str
    description: str
    cvss_score: Optional[float]
    severity: str
    timestamp: str  # ISO-8601 UTC timestamp


class CVEDatabaseManager:
    """Manages SQLite persistence for CVE records."""

    def __init__(self, db_path: str = "rbvm_intel.db") -> None:
        """Initializes the database manager and ensures schema exists.

        Args:
            db_path: Path to the SQLite database file.
        """
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        """Creates the CVE table if it does not already exist."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("PRAGMA foreign_keys = ON;")
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS cves (
                        id TEXT PRIMARY KEY,
                        description TEXT NOT NULL,
                        cvss_score REAL,
                        severity TEXT NOT NULL,
                        timestamp TEXT NOT NULL
                    );
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_cves_timestamp ON cves(timestamp);")
        except sqlite3.Error as exc:
            raise RuntimeError(f"Database initialization failed: {exc}") from exc

    @staticmethod
    def utc_now_iso() -> str:
        """Returns current UTC time as an ISO-8601 string."""
        return datetime.now(timezone.utc).isoformat()

    def cve_exists(self, cve_id: str) -> bool:
        """Checks whether a CVE ID already exists.

        Args:
            cve_id: CVE identifier (e.g., 'CVE-2025-12345').

        Returns:
            True if present, otherwise False.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.execute("SELECT 1 FROM cves WHERE id = ? LIMIT 1;", (cve_id,))
                return cur.fetchone() is not None
        except sqlite3.Error as exc:
            raise RuntimeError(f"Database query failed (cve_exists): {exc}") from exc

    def insert_cve(self, record: CVERecord) -> bool:
        """Inserts a CVE record if it does not already exist.

        Args:
            record: Normalized CVERecord instance.

        Returns:
            True if inserted, False if it already existed (dedup).
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.execute(
                    """
                    INSERT OR IGNORE INTO cves (id, description, cvss_score, severity, timestamp)
                    VALUES (?, ?, ?, ?, ?);
                    """,
                    (record.cve_id, record.description, record.cvss_score, record.severity, record.timestamp),
                )
                return cur.rowcount == 1
        except sqlite3.Error as exc:
            raise RuntimeError(f"Database insert failed (insert_cve): {exc}") from exc

    def insert_many(self, records: Iterable[CVERecord]) -> int:
        """Bulk inserts CVE records with deduplication.

        Args:
            records: Iterable of CVERecord objects.

        Returns:
            Count of newly inserted records.
        """
        records_list = list(records)
        if not records_list:
            return 0

        try:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.executemany(
                    """
                    INSERT OR IGNORE INTO cves (id, description, cvss_score, severity, timestamp)
                    VALUES (?, ?, ?, ?, ?);
                    """,
                    [
                        (r.cve_id, r.description, r.cvss_score, r.severity, r.timestamp)
                        for r in records_list
                    ],
                )
                # sqlite3 executemany rowcount is driver-dependent; do a deterministic count instead.
                inserted = conn.execute("SELECT changes();").fetchone()[0]
                return int(inserted)
        except sqlite3.Error as exc:
            raise RuntimeError(f"Database bulk insert failed (insert_many): {exc}") from exc
