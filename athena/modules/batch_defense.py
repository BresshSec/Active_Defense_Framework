"""Bounded, offline triage of a directory of suspicious files."""

import argparse
import hashlib
import json
import re
import sys
import zipfile
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path

from . import archive_defense, email_defense, office_defense
from .pdf_defense import make_pdf, run_check

OFFICE_SUFFIXES = {".doc", ".docm", ".docx", ".xls", ".xlsm", ".xlsx",
                   ".ppt", ".pptm", ".pptx", ".rtf"}


def collect_files(directory, recursive, max_files, exclude=None):
    candidates = directory.rglob("*") if recursive else directory.iterdir()
    files = []
    omitted = 0
    for path in candidates:
        if path.is_symlink() or not path.is_file() or (exclude and path.is_relative_to(exclude)):
            continue
        if len(files) < max_files:
            files.append(path)
        else:
            omitted = 1
            break
    return sorted(files), omitted


def scan_file(path, profile, max_size):
    size = path.stat().st_size
    if size > max_size:
        return {"status": "skipped", "output": f"Size {size} exceeds {max_size} byte limit", "size_bytes": size}
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    checks = {}
    notes = []
    type_result = run_check("file", ["file", "--", str(path)], 30)
    checks["file"] = type_result
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        if type_result["status"] == "ok" and "PDF document" not in type_result["output"]:
            notes.append("PDF extension does not match detected file type")
        checks["pdfid"] = run_check("pdfid", ["pdfid", str(path)], 30)
        if checks["pdfid"]["status"] == "ok":
            for label in ("/JS", "/JavaScript", "/OpenAction", "/Launch", "/EmbeddedFile"):
                match = re.search(r"^\s*" + re.escape(label) + r"\s+(\d+)\s*$",
                                  checks["pdfid"]["output"], re.MULTILINE)
                if match and int(match.group(1)):
                    notes.append(f"PDF contains {label}: {match.group(1)}")
        if profile == "deep":
            checks["qpdf"] = run_check("qpdf", ["qpdf", "--check", str(path)], 30)
            checks["pdf-parser"] = run_check("pdf-parser", ["pdf-parser", "-a", str(path)], 45)
    elif suffix == ".eml":
        try:
            message = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
            chosen = ["headers", "attachments"] + (["authentication", "links"] if profile == "deep" else [])
            findings, extra = email_defense.analyze(message, chosen)
            checks.update(findings)
            notes.extend(note for note in extra if not note.startswith("No alert") and not note.startswith("Authentication headers"))
        except (OSError, ValueError) as exc:
            checks["eml"] = {"status": "error", "output": str(exc)}
    elif suffix in OFFICE_SUFFIXES:
        checks["ooxml"] = office_defense.inspect_ooxml(path)
        if checks["ooxml"].get("count", 0):
            notes.append(f"OOXML contains {checks['ooxml']['count']} item(s) to review")
        if profile == "deep":
            checks["oleid"] = run_check("oleid", ["oleid", str(path)], 45)
            checks["mraptor"] = run_check("mraptor", ["mraptor", str(path)], 45)
    elif suffix == ".zip" and zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as archive:
                entries = archive.infolist()
            if len(entries) > archive_defense.MAX_MEMBERS:
                checks["zip"] = {"status": "skipped", "output": "More than 10,000 ZIP members"}
            else:
                selected = ["paths", "encryption"] + (["compression", "names"] if profile == "deep" else [])
                findings, extra = archive_defense.analyze(entries, selected)
                checks.update(findings)
                notes.extend(note for note in extra if not note.startswith("No alert"))
        except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
            checks["zip"] = {"status": "error", "output": str(exc)}
    if profile == "deep":
        checks["clamscan"] = run_check("clamscan", ["clamscan", "--no-summary", "--", str(path)], 90)
        clam = checks["clamscan"]
        if clam.get("exit_code") == 1 or " FOUND" in clam.get("output", ""):
            notes.append("ClamAV reported a detection")
    for name, result in checks.items():
        if result["status"] not in ("ok", "not_applicable"):
            notes.append(f"{name}: {result['status']} (review output)")
    lines = [f"SHA-256: {digest.hexdigest()}", f"Size: {size} bytes"]
    for name, result in checks.items():
        lines.append(f"\n[{name}] {result['status']}\n{result['output'][:2500]}")
    return {"status": "ok", "sha256": digest.hexdigest(), "size_bytes": size,
            "checks": checks, "observations": notes, "output": "\n".join(lines)[:15000]}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Batch triage with one aggregate report")
    parser.add_argument("directory", nargs="?", type=Path)
    parser.add_argument("-r", "--recursive", action="store_true")
    parser.add_argument("--profile", choices=("quick", "deep"), default="quick")
    parser.add_argument("--max-files", type=int, default=100)
    parser.add_argument("--max-size-mb", type=int, default=20)
    parser.add_argument("-o", "--output-dir", type=Path, default=Path("athena-report"))
    args = parser.parse_args(argv)
    if args.max_files < 1 or args.max_files > 1000 or args.max_size_mb < 1 or args.max_size_mb > 250:
        parser.error("Limits: 1-1000 files and 1-250 MB per file")
    if args.directory is None:
        try:
            raw = input("Directory path (or Q to quit): ").strip()
        except (EOFError, KeyboardInterrupt):
            return 130
        if raw.lower() == "q":
            return 0
        directory = Path(raw.strip("\"' ")).expanduser().resolve()
        choice = input("Profile [quick/deep] (default quick): ").strip().lower()
        if choice in ("quick", "deep"):
            args.profile = choice
        choice = input("Include subdirectories? [y/N]: ").strip().lower()
        args.recursive = choice in ("y", "yes")
    else:
        directory = args.directory.expanduser().resolve()
    if not directory.is_dir():
        parser.error("Directory not found")
    out = args.output_dir.expanduser().resolve()
    files, omitted = collect_files(directory, args.recursive, args.max_files, exclude=out)
    if not files:
        print("No regular files found.")
        return 0
    print(f"Scanning {len(files)} file(s), profile={args.profile}; {omitted} omitted by file limit")
    checks = {}
    manifest = hashlib.sha256()
    flagged = 0
    for index, path in enumerate(files, 1):
        relative = path.relative_to(directory).as_posix()
        print(f"[{index}/{len(files)}] {relative}", flush=True)
        try:
            result = scan_file(path, args.profile, args.max_size_mb * 1024 * 1024)
        except (OSError, ValueError) as exc:
            result = {"status": "error", "output": str(exc), "observations": ["Scan failed"]}
        checks[relative] = result
        manifest.update(relative.encode("utf-8", "replace") + b"\x00" + result.get("sha256", "").encode() + b"\n")
        if result.get("observations") or result["status"] != "ok":
            flagged += 1
    summary = [f"Scanned {len(files)} files; {flagged} with observations or incomplete checks"]
    if omitted:
        summary.append("At least one file omitted by the --max-files limit")
    summary.append("Observations are triage leads, not a malware verdict")
    data = {"module": "Athena Batch Defense", "file": str(directory), "size_bytes": sum(item.get("size_bytes", 0) for item in checks.values()),
            "sha256": manifest.hexdigest(), "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "profile": args.profile, "recursive": args.recursive, "observations": summary, "checks": checks}
    out.mkdir(parents=True, exist_ok=True)
    stem = "athena-batch-" + data["sha256"][:12]
    json_path = out / (stem + ".json")
    json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        report = out / (stem + ".pdf")
        pdf_data = dict(data)
        pdf_data["checks"] = {name: {"status": result["status"], "output": result["output"][:4000]}
                              for name, result in checks.items()}
        make_pdf(report, pdf_data)
    except ImportError:
        print("Install python3-reportlab to generate PDF reports.", file=sys.stderr)
        return 2
    print(f"Report: {report}\nRaw results: {json_path}")
    return 0

