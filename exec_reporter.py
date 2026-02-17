"""
exec_reporter.py

Executive reporting module for RBVM Orchestrator.
- Ingests Top Risk correlations JSON produced by risk_engine.py
- Generates a corporate-style PDF using FPDF:
  Title: "Enterprise Vulnerability & Risk Assessment"
  Includes Risk Posture Summary, findings table, timestamp, and page numbers
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fpdf import FPDF


@dataclass(frozen=True)
class Finding:
    """Represents one risk correlation row for reporting."""
    asset_name: str
    vulnerability_id: str
    risk_score: float
    remediation_path: str


class ExecutiveReportPDF(FPDF):
    """FPDF subclass with corporate header/footer (branding, timestamp, page numbers)."""

    def __init__(self, report_title: str, generated_ts_utc: str) -> None:
        """Initializes the PDF.

        Args:
            report_title: PDF title shown in the header.
            generated_ts_utc: Report generation timestamp (UTC) used in header.
        """
        super().__init__(orientation="P", unit="mm", format="A4")
        self.report_title = report_title
        self.generated_ts_utc = generated_ts_utc

        # Corporate-ish defaults
        self.set_auto_page_break(auto=True, margin=14)
        self.set_margins(left=14, top=14, right=14)

    def header(self) -> None:
        """Draws a clean corporate header on each page."""
        # Top rule
        self.set_draw_color(40, 40, 40)
        self.set_line_width(0.4)

        self.set_font("Helvetica", "B", 13)
        self.cell(0, 7, self.report_title, ln=1)

        self.set_font("Helvetica", "", 9)
        self.set_text_color(90, 90, 90)
        self.cell(0, 5, f"Generated (UTC): {self.generated_ts_utc}", ln=1)

        self.set_text_color(0, 0, 0)
        self.ln(1)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(6)

    def footer(self) -> None:
        """Draws page numbering at the bottom."""
        self.set_y(-12)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(90, 90, 90)
        self.cell(0, 8, f"Page {self.page_no()}", align="R")
        self.set_text_color(0, 0, 0)


class ExecutiveReporter:
    """Generates an executive PDF report from risk engine JSON artifacts."""

    def __init__(
        self,
        input_json_path: str,
        output_pdf_path: str = "Enterprise_Vulnerability_Risk_Assessment.pdf",
        logger: Optional[logging.Logger] = None,
    ) -> None:
        """Initializes the reporter.

        Args:
            input_json_path: Path to JSON file created by risk_engine.py.
            output_pdf_path: Output PDF filename/path.
            logger: Optional logger instance.
        """
        self.input_json_path = Path(input_json_path)
        self.output_pdf_path = Path(output_pdf_path)
        self.logger = logger or logging.getLogger(self.__class__.__name__)

    @staticmethod
    def _utc_now_iso() -> str:
        """Returns current UTC time as ISO-8601 string."""
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def load_risk_json(self) -> Dict[str, Any]:
        """Loads and validates the risk JSON artifact.

        Returns:
            Parsed JSON dict.

        Raises:
            FileNotFoundError: If JSON does not exist.
            ValueError: If JSON structure is invalid.
            RuntimeError: If JSON cannot be parsed.
        """
        if not self.input_json_path.exists():
            raise FileNotFoundError(f"Risk JSON artifact not found: {self.input_json_path}")

        try:
            payload = json.loads(self.input_json_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Failed to read/parse JSON: {exc}") from exc

        if not isinstance(payload, dict) or "results" not in payload:
            raise ValueError("Invalid risk JSON format: missing top-level 'results'.")

        if not isinstance(payload["results"], list):
            raise ValueError("Invalid risk JSON format: 'results' must be a list.")

        return payload

    @staticmethod
    def _recommend_remediation(
        risk_score: float,
        network_exposure: int,
        data_sensitivity: int,
        severity: str,
    ) -> str:
        """Determines a concise remediation path label.

        Heuristic intent:
          - High exposure: reduce blast radius first -> Network Segmentation
          - High sensitivity: tighten access & monitoring -> Access Control
          - Otherwise: standard mitigation -> Patching

        Args:
            risk_score: Weighted risk score.
            network_exposure: Exposure score 1-5.
            data_sensitivity: Sensitivity score 1-10.
            severity: CVE severity label.

        Returns:
            Remediation path string.
        """
        sev = (severity or "").upper()

        # Exposure-driven containment priority
        if network_exposure >= 4:
            return "Network Segmentation"

        # Data sensitivity driven control priority
        if data_sensitivity >= 8:
            return "Access Control"

        # High severity / high score generally leans patch-first if reachable
        if sev == "CRITICAL" or risk_score >= 80:
            return "Patching"

        return "Patching"

    def _to_findings(self, payload: Dict[str, Any]) -> List[Finding]:
        """Converts JSON payload to report findings with remediation labels.

        Args:
            payload: Parsed JSON from risk engine.

        Returns:
            List of Finding rows (sorted by descending risk score).
        """
        findings: List[Finding] = []

        for item in payload.get("results", []):
            try:
                asset = str(item.get("asset_name", "")).strip()
                cve_id = str(item.get("cve_id", "")).strip()
                risk = float(item.get("risk_score", 0.0))
                severity = str(item.get("severity", "UNKNOWN")).strip()

                net_exp = int(item.get("network_exposure", 1))
                data_sens = int(item.get("data_sensitivity", 1))

                if not asset or not cve_id:
                    continue

                remediation = self._recommend_remediation(
                    risk_score=risk,
                    network_exposure=net_exp,
                    data_sensitivity=data_sens,
                    severity=severity,
                )

                findings.append(
                    Finding(
                        asset_name=asset,
                        vulnerability_id=cve_id,
                        risk_score=risk,
                        remediation_path=remediation,
                    )
                )
            except (TypeError, ValueError):
                continue

        findings.sort(key=lambda f: f.risk_score, reverse=True)
        return findings

    @staticmethod
    def _compute_summary(findings: List[Finding]) -> Dict[str, Any]:
        """Computes a compact executive summary from findings.

        Args:
            findings: Finding rows.

        Returns:
            Dict with key summary metrics.
        """
        if not findings:
            return {
                "total_findings": 0,
                "avg_risk": 0.0,
                "max_risk": 0.0,
                "top_asset": "N/A",
                "remediation_breakdown": {},
            }

        total = len(findings)
        avg_risk = sum(f.risk_score for f in findings) / total
        max_risk = findings[0].risk_score

        # Top asset by max risk appearance
        asset_to_max: Dict[str, float] = {}
        for f in findings:
            asset_to_max[f.asset_name] = max(asset_to_max.get(f.asset_name, 0.0), f.risk_score)
        top_asset = max(asset_to_max.items(), key=lambda kv: kv[1])[0]

        # Remediation breakdown
        breakdown: Dict[str, int] = {}
        for f in findings:
            breakdown[f.remediation_path] = breakdown.get(f.remediation_path, 0) + 1

        return {
            "total_findings": total,
            "avg_risk": avg_risk,
            "max_risk": max_risk,
            "top_asset": top_asset,
            "remediation_breakdown": breakdown,
        }

    # -------------------------
    # PDF Rendering
    # -------------------------
    def generate_pdf(self) -> Path:
        """Generates the executive PDF report.

        Returns:
            Path to the generated PDF.

        Raises:
            RuntimeError: If PDF generation fails.
        """
        payload = self.load_risk_json()
        findings = self._to_findings(payload)
        summary = self._compute_summary(findings)

        title = "Enterprise Vulnerability & Risk Assessment"
        ts = self._utc_now_iso()
        pdf = ExecutiveReportPDF(report_title=title, generated_ts_utc=ts)
        pdf.add_page()

        # Risk Posture Summary
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Risk Posture Summary", ln=1)

        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(
            0,
            6,
            (
                f"Total high-priority correlations analyzed: {summary['total_findings']}\n"
                f"Average weighted risk score: {summary['avg_risk']:.2f}\n"
                f"Peak weighted risk score: {summary['max_risk']:.2f}\n"
                f"Highest-risk asset (by peak score): {summary['top_asset']}"
            ),
        )

        # Remediation distribution
        breakdown = summary.get("remediation_breakdown", {}) or {}
        if breakdown:
            pdf.ln(1)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6, "Recommended remediation distribution:", ln=1)
            pdf.set_font("Helvetica", "", 10)
            for k in sorted(breakdown.keys()):
                pdf.cell(0, 6, f"- {k}: {breakdown[k]}", ln=1)

        pdf.ln(4)

        # Findings Table
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Top Risk Findings", ln=1)

        # Table layout
        col_asset = 62
        col_vuln = 42
        col_risk = 28
        col_rem = 0  # auto remainder

        # Header row
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_fill_color(235, 235, 235)
        pdf.cell(col_asset, 8, "Asset Name", border=1, fill=True)
        pdf.cell(col_vuln, 8, "Vulnerability ID", border=1, fill=True)
        pdf.cell(col_risk, 8, "Risk Score", border=1, fill=True, align="R")
        pdf.cell(col_rem, 8, "Remediation Path", border=1, fill=True)
        pdf.ln()

        pdf.set_font("Helvetica", "", 10)

        if not findings:
            pdf.multi_cell(0, 6, "No correlated high-risk findings were produced by the risk engine.")
        else:
            for f in findings:
                # Simple row rendering; keep asset/vuln concise to preserve layout.
                asset_txt = f.asset_name[:40] + ("…" if len(f.asset_name) > 40 else "")
                vuln_txt = f.vulnerability_id[:18] + ("…" if len(f.vulnerability_id) > 18 else "")
                rem_txt = f.remediation_path

                pdf.cell(col_asset, 8, asset_txt, border=1)
                pdf.cell(col_vuln, 8, vuln_txt, border=1)
                pdf.cell(col_risk, 8, f"{f.risk_score:.2f}", border=1, align="R")
                pdf.cell(col_rem, 8, rem_txt, border=1)
                pdf.ln()

        # Closing note (executive tone)
        pdf.ln(6)
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_text_color(90, 90, 90)
        pdf.multi_cell(
            0,
            5,
            (
                "Note: Risk scores reflect a weighted prioritization model combining technical severity (CVSS) "
                "with enterprise context (data sensitivity and network exposure)."
            ),
        )
        pdf.set_text_color(0, 0, 0)

        try:
            pdf.output(str(self.output_pdf_path))
            self.logger.info("PDF generated: %s", self.output_pdf_path)
            return self.output_pdf_path
        except Exception as exc:
            raise RuntimeError(f"Failed to write PDF output: {exc}") from exc


def main() -> None:
    """CLI entry point.

    Usage:
        python exec_reporter.py /path/to/rbvm_top_risks_xxx.json
    """
    import sys

    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")

    if len(sys.argv) < 2:
        raise SystemExit("Usage: python exec_reporter.py <path_to_top_risks_json>")

    input_json = sys.argv[1]
    reporter = ExecutiveReporter(
        input_json_path=input_json,
        output_pdf_path="Enterprise_Vulnerability_Risk_Assessment.pdf",
    )
    out = reporter.generate_pdf()
    print(f"Report created: {out}")


if __name__ == "__main__":
    main()
