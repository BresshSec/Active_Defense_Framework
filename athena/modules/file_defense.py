"""Static triage for arbitrary files. No sample content is executed."""

import argparse
import hashlib
import json
import math
import re
import sys
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .pdf_defense import Check, find_urls, make_pdf, run_check

CHECKS = [
    Check("file", "Defense", "Identify real file type", lambda p: ["file", "--", str(p)]),
    Check("mime", "Defense", "Identify MIME type", lambda p: ["file", "--mime-type", "--", str(p)]),
    Check("clamscan", "Defense", "Check local antivirus signatures", lambda p: ["clamscan", "--no-summary", "--", str(p)]),
    Check("exiftool", "Defense", "Inspect metadata", lambda p: ["exiftool", str(p)]),
    Check("entropy", "Hunting", "Measure byte randomness", None),
    Check("strings", "Hunting", "Extract printable strings", None),
    Check("urls", "Hunting", "Find literal URL strings", None),
    Check("archive", "Hunting", "List ZIP members without extraction", None),
]


def choose_checks():
    selected = {c.key for c in CHECKS if c.category == "Defense"}
    while True:
        print("\nFile checks (* = selected):")
        for index, check in enumerate(CHECKS, 1):
            mark = "*" if check.key in selected else " "
            print(f" {index}. [{mark}] {check.category:7} {check.key:9} {check.description}")
        print("Numbers toggle; A=all, D=Defense, H=Hunting, R=reset, Enter=run, Q=quit")
        answer = input("File Defense> ").strip().lower()
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
        elif answer == "r":
            selected.clear()
        else:
            try:
                indices = {int(v.strip()) for v in answer.split(",")}
                if any(i < 1 or i > len(CHECKS) for i in indices):
                    raise ValueError
                for i in indices:
                    selected.symmetric_difference_update({CHECKS[i - 1].key})
            except ValueError:
                print("Invalid selection.")


def internal_check(key, path):
    if key == "urls":
        return find_urls(path)
    if path.stat().st_size > 100 * 1024 * 1024:
        return {"status": "skipped", "output": "File exceeds 100 MB analysis limit"}
    if key == "archive":
        if not zipfile.is_zipfile(path):
            return {"status": "ok", "output": "Not a ZIP archive"}
        try:
            with zipfile.ZipFile(path) as archive:
                members = archive.infolist()
                lines = [f"{entry.file_size:>12}  {entry.filename}" for entry in members[:500]]
                if len(members) > 500:
                    lines.append(f"... {len(members) - 500} more members omitted")
                return {"status": "ok", "output": "\n".join(lines) or "Empty ZIP archive",
                        "member_count": len(members)}
        except (OSError, zipfile.BadZipFile) as exc:
            return {"status": "error", "output": str(exc)}
    data = path.read_bytes()
    if key == "entropy":
        sample = data[:4 * 1024 * 1024]
        if not sample:
            value = 0.0
        else:
            counts = Counter(sample).values()
            value = -sum((n / len(sample)) * math.log2(n / len(sample)) for n in counts)
        return {"status": "ok", "output": f"Shannon entropy: {value:.3f} / 8 bits per byte\nSample: {len(sample)} bytes\nHigh entropy alone is not a malware indicator", "entropy": value}
    if key == "strings":
        matches = re.findall(rb"[\x20-\x7e]{6,}", data)
        lines = [s.decode("ascii", "replace")[:200] for s in matches[:300]]
        return {"status": "ok", "output": "\n".join(lines) or "No printable strings found",
                "string_count": len(matches), "note": "First 300 strings shown"}
    raise ValueError(key)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Athena File Defense: static file triage")
    parser.add_argument("file", nargs="?", type=Path)
    parser.add_argument("-o", "--output-dir", type=Path, default=Path("athena-report"))
    parser.add_argument("--timeout", type=int, default=45)
    parser.add_argument("--checks", help="Comma-separated keys, or all/defense/hunting")
    args = parser.parse_args(argv)
    if args.timeout < 1 or args.timeout > 600:
        parser.error("Timeout must be 1 to 600 seconds")
    if args.file is None:
        try:
            raw = input("File path (or Q to quit): ").strip()
        except (EOFError, KeyboardInterrupt):
            return 130
        if raw.lower() == "q":
            return 0
        path = Path(raw.strip("\"' ")).expanduser().resolve()
    else:
        path = args.file.expanduser().resolve()
    if not path.is_file():
        parser.error("File not found")
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
            chosen = choose_checks()
        except (EOFError, KeyboardInterrupt):
            return 130
    if not chosen:
        return 0
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    data = {"module": "Athena File Defense", "file": str(path), "size_bytes": path.stat().st_size,
            "sha256": digest.hexdigest(), "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "selected_checks": [c.key for c in chosen], "checks": {}}
    for check in chosen:
        print(f"[+] {check.category}: {check.key}", flush=True)
        data["checks"][check.key] = (run_check(check.key, check.build(path), args.timeout)
                                     if check.build else internal_check(check.key, path))
    notes = []
    clam = data["checks"].get("clamscan", {})
    if clam.get("exit_code") == 1 or " FOUND" in clam.get("output", ""):
        notes.append("ClamAV reported a detection; inspect full output")
    for key, result in data["checks"].items():
        if result["status"] not in ("ok", "exit_error") or (result["status"] == "exit_error" and key != "clamscan"):
            notes.append(f"{key}: {result['status']} (check incomplete)")
    if not notes:
        notes.append("No alert from selected checks; this does not prove the file is safe")
    data["observations"] = notes
    out = args.output_dir.expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    stem = "athena-file-" + digest.hexdigest()[:12]
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

