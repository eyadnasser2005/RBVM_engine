"""
risk_engine.py

RBVM Logic Engine:
- Loads CVEs from SQLite and assets from CSV
- Correlates vulnerabilities to assets via OS keyword/regex matching
- Computes weighted risk scores
- Persists Top-N correlations to a temporary JSON artifact for reporting
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Pattern, Tuple

import pandas as pd

from asset_manager import AssetManager
from database_manager import CVEDatabaseManager


@dataclass(frozen=True)
class CVEItem:
    """Normalized CVE model used by the risk engine."""
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    timestamp: str


@dataclass(frozen=True)
class RiskCorrelation:
    """Represents one asset-to-vulnerability correlation with computed risk."""
    asset_name: str
    os_platform: str
    data_sensitivity: int
    network_exposure: int
    cve_id: str
    severity: str
    cvss_score: float
    risk_score: float
    match_reason: str  # which regex/keyword family matched


class RiskEngine:
    """Performs asset-vulnerability correlation and weighted risk scoring."""

    def __init__(
        self,
        db_path: str = "rbvm_intel.db",
        assets_csv_path: str = "assets_enterprise.csv",
        logger: Optional[logging.Logger] = None,
    ) -> None:
        """Initializes the risk engine.

        Args:
            db_path: Path to SQLite database containing the CVE table.
            assets_csv_path: Path to the assets inventory CSV file.
            logger: Optional logger instance. If not provided, a class logger is used.
        """
        self.db_path = db_path
        self.assets_csv_path = assets_csv_path
        self.logger = logger or logging.getLogger(self.__class__.__name__)

    # -----------------------
    # Data Loading
    # -----------------------
    def load_assets(self) -> pd.DataFrame:
        """Loads assets from CSV into a pandas DataFrame.

        Returns:
            DataFrame with Asset_Name, OS_Platform, Data_Sensitivity_Score, Network_Exposure_Score.

        Raises:
            RuntimeError: If loading fails.
        """
        try:
            am = AssetManager(self.assets_csv_path)
            df = am.load_assets_dataframe()
            self.logger.info("Loaded %d assets from %s", len(df), self.assets_csv_path)
            return df
        except Exception as exc:
            raise RuntimeError(f"Failed to load assets: {exc}") from exc

    def load_vulnerabilities(self) -> List[CVEItem]:
        """Loads vulnerabilities from SQLite database.

        Returns:
            List of CVEItem records.

        Raises:
            RuntimeError: If DB read fails.
        """
        query = "SELECT id, description, cvss_score, severity, timestamp FROM cves;"
        try:
            # Reuse manager for initialization guarantees (table exists), but read directly.
            CVEDatabaseManager(self.db_path)

            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute(query).fetchall()

            items: List[CVEItem] = []
            for cve_id, description, cvss_score, severity, timestamp in rows:
                # Skip CVEs lacking usable score for risk math.
                if cvss_score is None:
                    continue
                try:
                    score = float(cvss_score)
                except (TypeError, ValueError):
                    continue

                items.append(
                    CVEItem(
                        cve_id=str(cve_id),
                        description=str(description or ""),
                        cvss_score=score,
                        severity=str(severity or "UNKNOWN").upper(),
                        timestamp=str(timestamp or ""),
                    )
                )

            self.logger.info("Loaded %d CVEs from %s (score-present).", len(items), self.db_path)
            return items

        except sqlite3.Error as exc:
            raise RuntimeError(f"Failed to read vulnerabilities from SQLite: {exc}") from exc

    # -----------------------
    # Correlation Logic
    # -----------------------
    @staticmethod
    def _platform_family(os_platform: str) -> str:
        """Maps an OS_Platform string to a platform family key.

        Args:
            os_platform: OS string from asset inventory (e.g., 'Windows Server 2019').

        Returns:
            Platform family key used for regex matching.
        """
        s = (os_platform or "").lower()

        if "windows" in s:
            return "windows"
        if "macos" in s or "os x" in s:
            return "macos"
        if "ubuntu" in s:
            return "ubuntu"
        if "rhel" in s or "red hat" in s:
            return "rhel"
        if "debian" in s:
            return "debian"
        if "linux" in s:
            return "linux_generic"

        # Network/Appliance OS families
        if "ios-xe" in s or "cisco" in s:
            return "cisco_ios"
        if "pan-os" in s or "palo alto" in s:
            return "panos"
        if "nx-os" in s:
            return "nxos"
        if "arubaos" in s or "aruba" in s:
            return "arubaos"
        if "asa" in s or "ftd" in s:
            return "cisco_asa"

        return "unknown"

    @staticmethod
    def _build_platform_patterns() -> Dict[str, Pattern[str]]:
        """Builds compiled regex patterns for platform-family matching.

        Returns:
            Dict mapping platform family -> compiled regex.
        """
        # Keep patterns conservative to reduce false positives.
        # These are intended for description-based matching (not CPE-grade precision).
        patterns: Dict[str, str] = {
            "windows": r"\bwindows\b|\bactive directory\b|\bmsft\b|\bmicrosoft\b|\bntlm\b",
            "macos": r"\bmacos\b|\bos x\b|\bapple\b",
            "ubuntu": r"\bubuntu\b",
            "rhel": r"\brhel\b|\bred hat\b",
            "debian": r"\bdebian\b",
            "linux_generic": r"\blinux\b|\bkernel\b|\bglibc\b|\bopenssl\b",
            "cisco_ios": r"\bcisco\b|\bios[\s-]?xe\b|\bios\b",
            "panos": r"\bpan-?os\b|\bpalo alto\b",
            "nxos": r"\bnx-?os\b",
            "arubaos": r"\baruba\b|\barubaos\b",
            "cisco_asa": r"\basa\b|\bftd\b|\bfirepower\b|\bcisco\b",
        }
        return {k: re.compile(v, re.IGNORECASE) for k, v in patterns.items()}

    @staticmethod
    def compute_risk_score(cvss_score: float, data_sensitivity: int, network_exposure: int) -> float:
        """Computes weighted risk score for a CVE-asset pair.

        Risk_Score = (CVSS_Score * Data_Sensitivity) + (Network_Exposure * 2.5)

        Args:
            cvss_score: CVSS base score (float).
            data_sensitivity: Asset sensitivity score (1-10).
            network_exposure: Asset exposure score (1-5).

        Returns:
            Weighted risk score as float.
        """
        return (cvss_score * float(data_sensitivity)) + (float(network_exposure) * 2.5)

    def correlate_top_risks(self, top_n: int = 10) -> List[RiskCorrelation]:
        """Performs correlation + scoring, returning top N highest-risk results.

        Args:
            top_n: Number of highest-risk correlations to return.

        Returns:
            List of top N RiskCorrelation objects.
        """
        assets_df = self.load_assets()
        cves = self.load_vulnerabilities()
        if assets_df.empty or not cves:
            self.logger.warning("Correlation skipped: assets=%d cves=%d", len(assets_df), len(cves))
            return []

        patterns = self._build_platform_patterns()

        # Pre-normalize CVE text once for speed.
        cve_text: List[Tuple[CVEItem, str]] = [(c, (c.description or "")) for c in cves]

        correlations: List[RiskCorrelation] = []

        for row in assets_df.itertuples(index=False):
            asset_name = str(getattr(row, "Asset_Name"))
            os_platform = str(getattr(row, "OS_Platform"))
            data_sens = int(getattr(row, "Data_Sensitivity_Score"))
            net_exp = int(getattr(row, "Network_Exposure_Score"))

            family = self._platform_family(os_platform)
            pat = patterns.get(family)

            if not pat:
                # Unknown platform family -> skip matching to avoid noise.
                continue

            for cve, desc in cve_text:
                if not desc:
                    continue

                if pat.search(desc):
                    risk = self.compute_risk_score(cve.cvss_score, data_sens, net_exp)
                    correlations.append(
                        RiskCorrelation(
                            asset_name=asset_name,
                            os_platform=os_platform,
                            data_sensitivity=data_sens,
                            network_exposure=net_exp,
                            cve_id=cve.cve_id,
                            severity=cve.severity,
                            cvss_score=cve.cvss_score,
                            risk_score=risk,
                            match_reason=family,
                        )
                    )

        if not correlations:
            self.logger.warning("No correlations found using description-based platform matching.")
            return []

        # Highest risk first; deterministic tie-breakers.
        top = sorted(
            correlations,
            key=lambda x: (x.risk_score, x.cvss_score, x.data_sensitivity, x.network_exposure),
            reverse=True,
        )[:top_n]

        self.logger.info("Generated %d correlations; returning top %d.", len(correlations), len(top))
        return top

    # -----------------------
    # Output Artifact
    # -----------------------
    def save_top_risks_to_temp_json(self, top_n: int = 10) -> Path:
        """Computes top correlations and writes them to a temp JSON file.

        Args:
            top_n: Number of highest-risk correlations to persist.

        Returns:
            Path to the temporary JSON file.

        Raises:
            RuntimeError: If writing fails.
        """
        top = self.correlate_top_risks(top_n=top_n)

        payload = {
            "generated_by": "risk_engine",
            "top_n": top_n,
            "count": len(top),
            "results": [asdict(r) for r in top],
        }

        try:
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", prefix="rbvm_top_risks_", delete=False, encoding="utf-8")
            with tmp as f:
                json.dump(payload, f, indent=2)
            path = Path(tmp.name)
            self.logger.info("Saved top risks JSON artifact: %s", path)
            return path
        except OSError as exc:
            raise RuntimeError(f"Failed to write temporary JSON artifact: {exc}") from exc


def main() -> None:
    """Runs the risk engine end-to-end and emits a temp JSON artifact."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")

    engine = RiskEngine(
        db_path="rbvm_intel.db",
        assets_csv_path="assets_enterprise.csv",
    )
    artifact_path = engine.save_top_risks_to_temp_json(top_n=10)
    print(f"Top risk correlations saved to: {artifact_path}")


if __name__ == "__main__":
    main()
