"""Inspect ZIP archives without extracting or executing members."""

import argparse
import hashlib
import json
import re
import stat
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from .pdf_defense import make_pdf

MAX_ARCHIVE = 250 * 1024 * 1024
MAX_MEMBERS = 10000
CHECKS = [
    ("inventory", "Defense", "Member names, sizes and types"),
    ("paths", "Defense", "Absolute paths and traversal"),
    ("encryption", "Defense", "Encrypted entries"),
    ("compression", "Hunting", "Compression ratios and large members"),
    ("names", "Hunting", "Executable, double extension and duplicate names"),
]
EXECUTABLE = (".exe", ".dll", ".scr", ".js", ".vbs", ".ps1", ".sh", ".lnk", ".bat", ".cmd")


def choose():
    selected = {key for key, category, _ in CHECKS if category == "Defense"}
    while True:
        print("\nArchive checks (* = selected):")
        for index, (key, category, description) in enumerate(CHECKS, 1):
            mark = "*" if key in selected else " "
            print(f" {index}. [{mark}] {category:7} {key:12} {description}")
        answer = input("Numbers toggle; A=all, D=Defense, H=Hunting, Enter=run, Q=quit > ").strip().lower()
        if not answer:
            if selected:
                return [key for key, _, _ in CHECKS if key in selected]
            print("Select at least one check.")
        elif answer == "q":
            return []
        elif answer == "a":
            selected = {key for key, _, _ in CHECKS}
        elif answer in ("d", "h"):
            selected = {key for key, category, _ in CHECKS if category.lower().startswith(answer)}
        else:
            try:
                indices = {int(v.strip()) for v in answer.split(",")}
                if any(i < 1 or i > len(CHECKS) for i in indices):
                    raise ValueError
                for i in indices:
                    selected.symmetric_difference_update({CHECKS[i - 1][0]})
            except ValueError:
                print("Invalid selection.")


def analyze(entries, selected):
    results = {}
    alerts = []
    if "inventory" in selected:
        lines = [f"{e.file_size:>12} {e.compress_size:>12} {e.filename[:200]}" for e in entries[:500]]
        if len(entries) > 500:
            lines.append(f"... {len(entries) - 500} more entries omitted")
        results["inventory"] = {"status": "ok", "output": "Uncompressed   Compressed   Name\n" + "\n".join(lines), "count": len(entries)}
    if "paths" in selected:
        bad = []
        for entry in entries:
            name = entry.filename.replace("\\", "/")
            parts = PurePosixPath(name).parts
            if name.startswith("/") or re.match(r"^[A-Za-z]:", name) or ".." in parts:
                bad.append(name)
            mode = (entry.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                bad.append(name + " (symlink)")
        results["paths"] = {"status": "ok", "output": "\n".join(bad[:200]) or "No traversal, absolute paths or symlinks found", "count": len(bad)}
        if bad:
            alerts.append(f"{len(bad)} unsafe path or symlink entry/entries found")
    if "encryption" in selected:
        names = [e.filename for e in entries if e.flag_bits & 1]
        results["encryption"] = {"status": "ok", "output": "\n".join(names[:200]) or "No encrypted entries", "count": len(names)}
        if names:
            alerts.append(f"{len(names)} encrypted archive entries cannot be inspected here")
    if "compression" in selected:
        suspect = []
        for entry in entries:
            ratio = entry.file_size / max(entry.compress_size, 1)
            if entry.file_size >= 100 * 1024 * 1024 or (entry.file_size >= 1024 * 1024 and ratio >= 100):
                suspect.append(f"{entry.filename[:150]} | {entry.file_size} bytes | {ratio:.1f}:1")
        results["compression"] = {"status": "ok", "output": "\n".join(suspect[:200]) or "No unusually large or highly compressed entries", "count": len(suspect)}
        if suspect:
            alerts.append(f"{len(suspect)} large or highly compressed entries warrant review")
    if "names" in selected:
        seen = set()
        suspect = []
        for entry in entries:
            name = entry.filename
            base = PurePosixPath(name.replace("\\", "/")).name
            lower = base.lower()
            if lower in seen:
                suspect.append(name + " (duplicate basename)")
            seen.add(lower)
            if lower.endswith(EXECUTABLE) or base.count(".") >= 2:
                suspect.append(name + " (review extension)")
        results["names"] = {"status": "ok", "output": "\n".join(suspect[:200]) or "No flagged filenames", "count": len(suspect)}
        if suspect:
            alerts.append(f"{len(suspect)} filename flags found")
    if not alerts:
        alerts.append("No alert from selected checks; archive contents were not opened")
    return results, alerts


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline ZIP archive triage")
    parser.add_argument("archive", nargs="?", type=Path)
    parser.add_argument("-o", "--output-dir", type=Path, default=Path("athena-report"))
    parser.add_argument("--checks", help="Comma-separated keys, or all/defense/hunting")
    args = parser.parse_args(argv)
    if args.archive is None:
        try:
            raw = input("ZIP path (or Q to quit): ").strip()
        except (EOFError, KeyboardInterrupt):
            return 130
        if raw.lower() == "q":
            return 0
        path = Path(raw.strip("\"' ")).expanduser().resolve()
    else:
        path = args.archive.expanduser().resolve()
    if not path.is_file():
        parser.error("Archive not found")
    if path.stat().st_size > MAX_ARCHIVE:
        parser.error("Archive exceeds 250 MB limit")
    if not zipfile.is_zipfile(path):
        parser.error("This module currently supports ZIP files only")
    if args.checks:
        values = [v.strip().lower() for v in args.checks.split(",")]
        if values == ["all"]:
            selected = [key for key, _, _ in CHECKS]
        elif values in (["defense"], ["hunting"]):
            selected = [key for key, category, _ in CHECKS if category.lower() == values[0]]
        else:
            unknown = set(values) - {key for key, _, _ in CHECKS}
            if unknown:
                parser.error("Unknown check(s): " + ", ".join(sorted(unknown)))
            selected = values
    else:
        try:
            selected = choose()
        except (EOFError, KeyboardInterrupt):
            return 130
    if not selected:
        return 0
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        parser.error(str(exc))
    if len(entries) > MAX_MEMBERS:
        parser.error("Archive exceeds 10,000 member limit")
    results, observations = analyze(entries, selected)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    data = {"module": "Athena Archive Defense", "file": str(path), "size_bytes": path.stat().st_size,
            "sha256": digest, "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "selected_checks": selected, "observations": observations, "checks": results}
    out = args.output_dir.expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    stem = "athena-archive-" + digest[:12]
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

