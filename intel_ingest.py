"""
intel_ingest.py

Threat intel ingestion for RBVM: fetches latest CRITICAL CVEs from NIST NVD API
and persists normalized records into SQLite with deduplication.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import requests

from database_manager import CVEDatabaseManager, CVERecord

NVD_CVE_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def configure_logging() -> None:
    """Configures application logging."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)sZ | %(levelname)s | %(name)s | %(message)s",
    )
    # Ensure UTC-ish feel in timestamps (logging uses local time by default).
    logging.Formatter.converter = time_gmtime  # type: ignore[name-defined]


def time_gmtime(*args: Any) -> Any:
    """Helper to format logging timestamps as UTC."""
    import time
    return time.gmtime(*args)


def _iso_utc(dt: datetime) -> str:
    """Converts datetime to ISO-8601 UTC string (no offset ambiguity)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _get_api_headers() -> Dict[str, str]:
    """Builds headers for NVD API calls, including optional API key.

    Returns:
        Headers dictionary for requests.
    """
    headers = {
        "User-Agent": "RBVM-Orchestrator/1.0 (Security Engineering; contact: security@example.com)",
        "Accept": "application/json",
    }
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        # NVD documentation: apiKey passed via request header.
        headers["apiKey"] = api_key
    return headers


def _extract_description(cve_obj: Dict[str, Any]) -> str:
    """Extracts the best English description from an NVD CVE object.

    Args:
        cve_obj: The "cve" object from NVD response.

    Returns:
        Description string (may be empty if missing).
    """
    descriptions = cve_obj.get("descriptions", []) or []
    for d in descriptions:
        if (d.get("lang") or "").lower() == "en":
            return (d.get("value") or "").strip()
    # fallback: first available
    if descriptions:
        return (descriptions[0].get("value") or "").strip()
    return ""


def _extract_best_cvss(cve_obj: Dict[str, Any]) -> Tuple[Optional[float], str]:
    """Extracts a CVSS base score and qualitative severity.

    Preference order:
      1) CVSS v3.x (if present)
      2) CVSS v4.0 (if present)
      3) None

    Args:
        cve_obj: The "cve" object from NVD response.

    Returns:
        Tuple of (cvss_score, severity_string).
    """
    metrics = cve_obj.get("metrics", {}) or {}

    # CVSS v3.x
    v3_list = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
    if v3_list:
        data = (v3_list[0] or {}).get("cvssData", {}) or {}
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or "UNKNOWN"
        try:
            return (float(score) if score is not None else None, str(severity).upper())
        except (TypeError, ValueError):
            return (None, str(severity).upper())

    # CVSS v4.0 (if present)
    v4_list = metrics.get("cvssMetricV40") or []
    if v4_list:
        data = (v4_list[0] or {}).get("cvssData", {}) or {}
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or "UNKNOWN"
        try:
            return (float(score) if score is not None else None, str(severity).upper())
        except (TypeError, ValueError):
            return (None, str(severity).upper())

    return (None, "UNKNOWN")


def fetch_recent_critical_cves(limit: int = 30, lookback_days: int = 120, timeout_s: int = 20) -> List[CVERecord]:
    """Fetches the most recent CRITICAL CVEs from NIST NVD and normalizes them.

    This pulls a bounded lookback window (default 120 days to align with NVD date-range constraints),
    then sorts locally by published date and returns the top `limit`.

    Args:
        limit: Number of CVEs to return (most recent).
        lookback_days: How far back to query (max 120 recommended for NVD pub date range).
        timeout_s: HTTP timeout in seconds.

    Returns:
        List of normalized CVERecord objects.

    Raises:
        RuntimeError: On network/HTTP/parse failures.
    """
    logger = logging.getLogger("intel_ingest")
    end_dt = datetime.now(timezone.utc)
    start_dt = end_dt - timedelta(days=lookback_days)

    params = {
        "pubStartDate": _iso_utc(start_dt),
        "pubEndDate": _iso_utc(end_dt),
        # Request by qualitative severity:
        "cvssV3Severity": "CRITICAL",
        "noRejected": "",  # exclude rejected CVEs
        "resultsPerPage": 2000,
        "startIndex": 0,
    }

    try:
        logger.info("Querying NVD for CRITICAL CVEs (lookback_days=%s)...", lookback_days)
        resp = requests.get(
            NVD_CVE_API_BASE,
            headers=_get_api_headers(),
            params=params,
            timeout=timeout_s,
        )
        if resp.status_code != 200:
            # NVD sometimes returns a helpful 'message' in headers on 4xx.
            msg = resp.headers.get("message") or resp.text[:300]
            raise RuntimeError(f"NVD API error {resp.status_code}: {msg}")

        payload = resp.json()
        vulns = payload.get("vulnerabilities", []) or []
        if not isinstance(vulns, list):
            raise RuntimeError("Unexpected NVD response shape: 'vulnerabilities' is not a list")

        normalized: List[Tuple[datetime, CVERecord]] = []

        for item in vulns:
            cve = (item or {}).get("cve", {}) or {}
            cve_id = (cve.get("id") or "").strip()
            if not cve_id:
                continue

            published_str = cve.get("published")
            try:
                # Example: "2025-01-01T12:34:56.789"
                published_dt = datetime.fromisoformat(str(published_str).replace("Z", "+00:00"))
                published_dt = published_dt.astimezone(timezone.utc)
            except Exception:
                # If published missing or unparsable, treat as oldest.
                published_dt = datetime(1970, 1, 1, tzinfo=timezone.utc)

            description = _extract_description(cve)
            cvss_score, severity = _extract_best_cvss(cve)

            normalized.append(
                (
                    published_dt,
                    CVERecord(
                        cve_id=cve_id,
                        description=description,
                        cvss_score=cvss_score,
                        severity=severity,
                        timestamp=CVEDatabaseManager.utc_now_iso(),
                    ),
                )
            )

        # Sort by published date (desc) and cap to limit.
        normalized.sort(key=lambda t: t[0], reverse=True)
        top = [rec for _, rec in normalized[:limit]]

        logger.info("Fetched %s normalized CRITICAL CVEs (returning top %s).", len(normalized), len(top))
        return top

    except requests.RequestException as exc:
        raise RuntimeError(f"Network error while calling NVD API: {exc}") from exc
    except ValueError as exc:
        raise RuntimeError(f"JSON parse error from NVD API response: {exc}") from exc


def save_deduped(db: CVEDatabaseManager, records: List[CVERecord]) -> int:
    """Deduplicates records (in-batch + DB) then saves them.

    Args:
        db: CVEDatabaseManager instance.
        records: List of CVERecord objects to persist.

    Returns:
        Number of newly inserted records.
    """
    logger = logging.getLogger("intel_ingest")

    # In-batch dedup (defensive).
    seen: Set[str] = set()
    unique: List[CVERecord] = []
    for r in records:
        if r.cve_id in seen:
            continue
        seen.add(r.cve_id)
        unique.append(r)

    if not unique:
        logger.info("No records to save after in-batch dedup.")
        return 0

    inserted = db.insert_many(unique)
    logger.info("Inserted %s new CVEs (dedup handled by primary key).", inserted)
    return inserted


def main() -> None:
    """Entry point for ingestion run."""
    configure_logging()
    logger = logging.getLogger("intel_ingest")

    try:
        db = CVEDatabaseManager(db_path=os.getenv("RBVM_DB_PATH", "rbvm_intel.db"))
        records = fetch_recent_critical_cves(limit=30)
        save_deduped(db, records)
        logger.info("Ingestion completed successfully.")
    except Exception as exc:
        logger.exception("Ingestion failed: %s", exc)
        raise


if __name__ == "__main__":
    main()
