"""Run local YARA triage rules against a file or directory."""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .pdf_defense import make_pdf, run_check

DEFAULT_RULES = Path(__file__).resolve().parents[2] / "rules" / "athena_triage.yar"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline YARA triage")
    parser.add_argument("target", nargs="?", type=Path)
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES,
                        help="Local .yar rules file; bundled triage rules by default")
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("-o", "--output-dir", type=Path, default=Path("athena-report"))
    args = parser.parse_args(argv)
    if args.timeout < 1 or args.timeout > 600:
        parser.error("Timeout must be 1 to 600 seconds")
    if args.target is None:
        try:
            raw = input("File or directory for YARA (or Q to quit): ").strip()
        except (EOFError, KeyboardInterrupt):
            return 130
        if raw.lower() == "q":
            return 0
        target = Path(raw.strip("\"' ")).expanduser().resolve()
    else:
        target = args.target.expanduser().resolve()
    rules = args.rules.expanduser().resolve()
    if not target.exists() or not (target.is_file() or target.is_dir()):
        parser.error("Target not found")
    if not rules.is_file():
        parser.error("Rules file not found")
    if rules.stat().st_size > 1024 * 1024:
        parser.error("Rules file exceeds 1 MB limit")
    command = ["yara", "--no-follow-symlinks", "--timeout", str(args.timeout),
               "--skip-larger", str(20 * 1024 * 1024)]
    if target.is_dir():
        command.append("--recursive")
    command += [str(rules), str(target)]
    result = run_check("yara", command, args.timeout + 10)
    if result.get("exit_code") == 0:
        hits = bool(result["output"].strip())
        notes = (["YARA produced match or warning output; review the rule names and targets"] if hits else
                 ["No match from selected rules; this does not prove safety"])
    else:
        notes = [f"YARA check {result['status']}; inspect output"]
    rules_hash = hashlib.sha256(rules.read_bytes()).hexdigest()
    if target.is_file():
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        size = target.stat().st_size
    else:
        digest = rules_hash
        size = 0
    data = {"module": "Athena YARA Defense", "file": str(target), "size_bytes": size,
            "sha256": digest, "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "rules": str(rules), "rules_sha256": rules_hash,
            "observations": notes, "checks": {"yara": result}}
    out = args.output_dir.expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = "athena-yara-" + digest[:12] + "-" + stamp
    json_path = out / (stem + ".json")
    json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        report = out / (stem + ".pdf")
        make_pdf(report, data)
    except ImportError:
        print("Install python3-reportlab to generate PDF reports.", file=sys.stderr)
        return 2
    print(f"Report: {report}\nRaw results: {json_path}")
    return 0

