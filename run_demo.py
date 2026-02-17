import os
import re
import sys
import subprocess
from pathlib import Path


def run(cmd: list[str]) -> str:
    """Run a command and return stdout (also prints live output)."""
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out_lines = []
    assert p.stdout is not None
    for line in p.stdout:
        print(line, end="")  # live progress for recruiter
        out_lines.append(line)
    rc = p.wait()
    if rc != 0:
        raise RuntimeError(f"Command failed ({rc}): {' '.join(cmd)}")
    return "".join(out_lines)


def main() -> None:
    root = Path(__file__).resolve().parent
    os.chdir(root)

    print("\n[VULN-CORRELATE] Running full demo pipeline...\n")

    # 1) Ingest CVEs
    run([sys.executable, "intel_ingest.py"])

    # 2) Create assets
    run([sys.executable, "asset_manager.py"])

    # 3) Correlate + score (captures JSON output path)
    out = run([sys.executable, "risk_engine.py"])

    # Try to extract the JSON path printed by risk_engine.py
    # Example line: "Top risk correlations saved to: /tmp/rbvm_top_risks_xxxxx.json"
    m = re.search(r"saved to:\s*(.+rbvm_top_risks_[^\s]+\.json)", out, re.IGNORECASE)
    if not m:
        # fallback: look for any rbvm_top_risks_*.json mention
        m = re.search(r"(/.*rbvm_top_risks_[^\s]+\.json)", out)
    if not m:
        raise RuntimeError("Could not find the generated top risks JSON path in output.")

    json_path = m.group(1).strip()
    print(f"\n[VULN-CORRELATE] Using top risks JSON: {json_path}\n")

    # 4) Generate PDF
    run([sys.executable, "exec_reporter.py", json_path])

    # exec_reporter writes PDF in current directory; confirm it exists
    pdf = root / "Enterprise_Vulnerability_Risk_Assessment.pdf"
    if pdf.exists():
        print(f"\n✅ Demo complete. PDF generated:\n{pdf}\n")
    else:
        print("\n✅ Demo complete. (PDF should have been generated; check project directory.)\n")


if __name__ == "__main__":
    main()
