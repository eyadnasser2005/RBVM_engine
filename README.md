# RBVM-Engine
A small Risk-Based Vulnerability Management (RBVM) demo that pulls live CRITICAL CVEs from NIST NVD, stores them in SQLite with deduplication, correlates them against a simulated enterprise asset inventory, calculates a weighted “business risk” score, and generates an executive-style PDF remediation summary.

## What this demonstrates (in plain English)
- Automated ingestion of live CVE intelligence (NIST NVD)
- Persistent storage + deduplication in SQLite (no duplicate CVEs)
- Asset context weighting (Data Sensitivity 1–10, Network Exposure 1–5)
- Quantitative risk scoring and ranked remediation output
- Executive reporting via PDF generation

## How it works (pipeline)
1) `intel_ingest.py` pulls the most recent CRITICAL CVEs from NVD and writes them to `rbvm_intel.db`
2) `asset_manager.py` generates a realistic `assets_enterprise.csv` (you do NOT need to create your own seed file)
3) `risk_engine.py` correlates CVEs to assets and outputs a temp JSON artifact (`rbvm_top_risks_*.json`)
4) `exec_reporter.py` converts that JSON into `Enterprise_Vulnerability_Risk_Assessment.pdf`

## Risk scoring model
Risk Score = (CVSS × Data Sensitivity) + (Network Exposure × 2.5)

- CVSS is technical severity from NVD (0–10)
- Data Sensitivity is business criticality (1–10)
- Network Exposure is attack surface exposure (1–5)

## Quick Demo (One Command)

```bash
pip install -r requirements.txt
python run_demo.py
