"""Static Microsoft Office document triage."""

import argparse
import hashlib
import json
import re
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from .pdf_defense import Check, make_pdf, run_check

CHECKS = [
    Check("file", "Defense", "Identify actual file type", lambda p: ["file", "--", str(p)]),
    Check("oleid", "Defense", "Detect OLE risk indicators", lambda p: ["oleid", str(p)]),
    Check("mraptor", "Defense", "Triage suspicious macros", lambda p: ["mraptor", str(p)]),
    Check("clamscan", "Defense", "Check local antivirus signatures", lambda p: ["clamscan", "--no-summary", "--", str(p)]),
    Check("olevba", "Hunting", "Inspect macro indicators", lambda p: ["olevba", "--analysis", str(p)]),
    Check("msodde", "Hunting", "Find DDE fields", lambda p: ["msodde", str(p)]),
    Check("ooxml", "Hunting", "Inspect OOXML macros, external links and embeddings", None),
]


def choose():
    selected = {c.key for c in CHECKS if c.category == "Defense"}
    while True:
        print("\nOffice checks (* = selected):")
        for index, check in enumerate(CHECKS, 1):
            mark = "*" if check.key in selected else " "
            print(f" {index}. [{mark}] {check.category:7} {check.key:9} {check.description}")
        answer = input("Numbers toggle; A=all, D=Defense, H=Hunting, Enter=run, Q=quit > ").strip().lower()
        if not answer:
            if selected:
                return [c for c in CHECKS if c.key in selected]
            print("Select at least one check.")
        elif answer == "q":
            return []
        elif answer == "a":
            selected = {c.key for c in CHECKS}
        elif answer in ("d", "h"):
            selected = {c.key for c in CHECKS if c.category.lower().startswith(answer)}
        else:
            try:
                numbers = {int(v.strip()) for v in answer.split(",")}
                if any(n < 1 or n > len(CHECKS) for n in numbers):
                    raise ValueError
                for number in numbers:
                    selected.symmetric_difference_update({CHECKS[number - 1].key})
            except ValueError:
                print("Invalid selection.")


def inspect_ooxml(path):
    if not zipfile.is_zipfile(path):
        return {"status": "not_applicable", "output": "Not an OOXML ZIP container"}
    findings = []
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if len(entries) > 10000:
                return {"status": "skipped", "output": "More than 10,000 package members"}
            for entry in entries:
                name = entry.filename.lower()
                if "vbaproject.bin" in name:
                    findings.append("Macro project: " + entry.filename)
                if "/embeddings/" in name or name.startswith("embeddings/"):
                    findings.append("Embedded object: " + entry.filename)
                if name.endswith(".rels") and entry.file_size <= 2 * 1024 * 1024:
                    content = archive.read(entry)
                    if re.search(rb'TargetMode\s*=\s*["\']External["\']', content, re.IGNORECASE):
                        findings.append("External relationship: " + entry.filename)
    except (OSError, zipfile.BadZipFile, RuntimeError, ValueError) as exc:
        return {"status": "error", "output": str(exc)}
    return {"status": "ok", "output": "\n".join(findings[:200]) or "No macro projects, embeddings or external relationships found",
            "count": len(findings)}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Static Office document triage")
    parser.add_argument("document", nargs="?", type=Path)
    parser.add_argument("-o", "--output-dir", type=Path, default=Path("athena-report"))
    parser.add_argument("--timeout", type=int, default=45)
    parser.add_argument("--checks", help="Comma-separated keys, or all/defense/hunting")
    args = parser.parse_args(argv)
    if args.timeout < 1 or args.timeout > 600:
        parser.error("Timeout must be 1 to 600 seconds")
    if args.document is None:
        try:
            raw = input("Office document path (or Q to quit): ").strip()
        except (EOFError, KeyboardInterrupt):
            return 130
        if raw.lower() == "q":
            return 0
        path = Path(raw.strip("\"' ")).expanduser().resolve()
    else:
        path = args.document.expanduser().resolve()
    if not path.is_file():
        parser.error("Document not found")
    if path.stat().st_size > 100 * 1024 * 1024:
        parser.error("Document exceeds 100 MB limit")
    if args.checks:
        values = [v.strip().lower() for v in args.checks.split(",")]
        if values == ["all"]:
            chosen = CHECKS
        elif values in (["defense"], ["hunting"]):
            chosen = [c for c in CHECKS if c.category.lower() == values[0]]
        else:
            unknown = set(values) - {c.key for c in CHECKS}
            if unknown:
                parser.error("Unknown check(s): " + ", ".join(sorted(unknown)))
            chosen = [c for c in CHECKS if c.key in values]
    else:
        try:
            chosen = choose()
        except (EOFError, KeyboardInterrupt):
            return 130
    if not chosen:
        return 0
    raw_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    data = {"module": "Athena Office Defense", "file": str(path), "size_bytes": path.stat().st_size,
            "sha256": raw_hash, "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "selected_checks": [c.key for c in chosen], "checks": {}}
    for check in chosen:
        print(f"[+] {check.category}: {check.key}", flush=True)
        data["checks"][check.key] = (inspect_ooxml(path) if check.key == "ooxml"
                                     else run_check(check.key, check.build(path), args.timeout))
    observations = []
    ooxml = data["checks"].get("ooxml", {})
    if ooxml.get("count", 0):
        observations.append(f"OOXML: {ooxml['count']} item(s) warrant review")
    clam = data["checks"].get("clamscan", {})
    if clam.get("exit_code") == 1 or " FOUND" in clam.get("output", ""):
        observations.append("ClamAV reported a detection")
    for key, result in data["checks"].items():
        if result["status"] not in ("ok", "not_applicable"):
            observations.append(f"{key}: {result['status']} (inspect output)")
    data["observations"] = observations or ["No alert from selected checks; safety is not established"]
    out = args.output_dir.expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    stem = "athena-office-" + raw_hash[:12]
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

