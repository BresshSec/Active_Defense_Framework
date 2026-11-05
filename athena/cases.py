"""Local case folders and minimal manifests for Athena runs."""

import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path.home() / "AthenaDefense" / "cases"


def create_case(module, root=ROOT):
    now = datetime.now(timezone.utc)
    case_id = now.strftime("AD-%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
    case_dir = root / case_id
    case_dir.mkdir(parents=True, mode=0o700)
    return case_id, case_dir


def save_manifest(case_id, case_dir, module, started, output_dir, result_code):
    artifacts = []
    if output_dir.is_dir():
        started_ts = datetime.fromisoformat(started).timestamp()
        artifacts = [str(path) for path in sorted(output_dir.iterdir())
                     if path.is_file() and path.suffix in (".json", ".pdf")
                     and path.stat().st_mtime >= started_ts - 1]
    data = {"case_id": case_id, "module": module, "started_utc": started,
            "finished_utc": datetime.now(timezone.utc).isoformat(),
            "result_code": result_code, "output_dir": str(output_dir), "artifacts": artifacts}
    manifest = case_dir / "case.json"
    manifest.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.chmod(manifest, 0o600)
    return manifest


def list_cases(root=ROOT):
    if not root.is_dir():
        print("No cases yet.")
        return 0
    cases = sorted((p for p in root.iterdir() if p.is_dir()), reverse=True)
    if not cases:
        print("No cases yet.")
        return 0
    print(f"Athena cases in {root}\n")
    for case_dir in cases[:50]:
        manifest = case_dir / "case.json"
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
            print(f"{data['case_id']}  {data['module']:8}  exit={data['result_code']}  {data['output_dir']}")
        except (OSError, ValueError, KeyError):
            print(f"{case_dir.name}  (incomplete)")
    return 0

