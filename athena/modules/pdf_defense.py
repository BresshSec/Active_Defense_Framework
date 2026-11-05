#!/usr/bin/env python3
"""Athena PDF Defense: interactive, local PDF triage for Kali Linux."""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

RED = "\033[31m"
RESET = "\033[0m"
BANNER = r"""
    _   _   _                               ____  ____  _____
   / \ | |_| |__   ___ _ __   __ _         |  _ \|  _ \|  ___|
  / _ \| __| '_ \ / _ \ '_ \ / _` |        | |_) | | | | |_ 
 / ___ \ |_| | | |  __/ | | | (_| |        |  __/| |_| |  _|
/_/   \_\__|_| |_|\___|_| |_|\__,_|        |_|   |____/|_|
             Athena PDF Defense
     a pdf active defense framework made by Bressh
"""

@dataclass(frozen=True)
class Check:
    key: str
    category: str
    description: str
    build: object


CHECKS = [
    Check("file", "Defense", "Identify real file type", lambda p: ["file", "--", str(p)]),
    Check("pdfinfo", "Defense", "Pages, encryption, metadata", lambda p: ["pdfinfo", str(p)]),
    Check("pdfid", "Defense", "PDF action and script keywords", lambda p: ["pdfid", str(p)]),
    Check("qpdf", "Defense", "Validate PDF structure", lambda p: ["qpdf", "--check", str(p)]),
    Check("clamscan", "Defense", "Local antivirus signatures", lambda p: ["clamscan", "--no-summary", "--", str(p)]),
    Check("pdftotext", "Hunting", "Extract readable text", lambda p: ["pdftotext", str(p), "-"]),
    Check("pdf-parser", "Hunting", "Enumerate PDF objects", lambda p: ["pdf-parser", "-a", str(p)]),
    Check("exiftool", "Hunting", "Inspect document metadata", lambda p: ["exiftool", str(p)]),
    Check("pdfimages", "Hunting", "List embedded page images", lambda p: ["pdfimages", "-list", str(p)]),
    Check("urls", "Hunting", "Find URL strings without visiting", None),
]


def select_checks():
    print("\nAvailable checks (* = selected):")
    selected = {check.key for check in CHECKS if check.category == "Defense"}
    while True:
        for index, check in enumerate(CHECKS, 1):
            mark = "*" if check.key in selected else " "
            print(f" {index:2}. [{mark}] {check.category:7} {check.key:12} {check.description}")
        print("\nType numbers (e.g. 2,7,11), A=all, D=Defense, H=Hunting, R=reset, Enter=run, Q=quit")
        answer = input("athena> ").strip().lower()
        if not answer:
            if selected:
                return [check for check in CHECKS if check.key in selected]
            print("Select at least one check.")
        elif answer == "q":
            return []
        elif answer == "a":
            selected = {check.key for check in CHECKS}
        elif answer in ("d", "h"):
            category = "Defense" if answer == "d" else "Hunting"
            selected = {check.key for check in CHECKS if check.category == category}
        elif answer == "r":
            selected.clear()
        else:
            try:
                numbers = {int(part.strip()) for part in answer.split(",")}
                if any(n < 1 or n > len(CHECKS) for n in numbers):
                    raise ValueError
                for number in numbers:
                    key = CHECKS[number - 1].key
                    selected.symmetric_difference_update({key})
            except ValueError:
                print("Invalid selection.")


def find_urls(pdf):
    # Passive string extraction; no requests are made to these addresses.
    if pdf.stat().st_size > 100 * 1024 * 1024:
        return {"status": "skipped", "command": ["internal", "passive-url-scan"],
                "output": "File exceeds 100 MB URL scan limit", "count": 0}
    data = pdf.read_bytes()
    patterns = [rb"https?://[^\s<>()\[\]{}\x00-\x1f\x7f\"']{3,300}",
                rb"h\x00t\x00t\x00p\x00s?\x00:\x00/\x00/\x00(?:[^\x00-\x1f]\x00){3,300}"]
    urls = set()
    for pattern in patterns:
        for match in re.finditer(pattern, data, re.IGNORECASE):
            value = match.group(0).replace(b"\x00", b"").decode("utf-8", "replace")
            urls.add(value.rstrip(".,;"))
            if len(urls) >= 200:
                break
    return {"status": "ok", "command": ["internal", "passive-url-scan"],
            "output": "\n".join(sorted(urls)) if urls else "No literal URL strings found",
            "count": len(urls), "note": "Compressed or encoded URLs may be missed"}


def run_check(name, command, timeout):
    if not shutil.which(command[0]):
        return {"status": "unavailable", "command": command, "output": "Tool not installed"}
    try:
        result = subprocess.run(command, capture_output=True, text=True, errors="replace",
                                timeout=timeout, stdin=subprocess.DEVNULL, check=False)
        output = (result.stdout + "\n" + result.stderr).strip()
        return {"status": "ok" if result.returncode == 0 else "exit_error",
                "exit_code": result.returncode, "command": command,
                "output": output[:100000], "truncated": len(output) > 100000}
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "command": command, "output": f"Exceeded {timeout}s"}
    except OSError as exc:
        return {"status": "error", "command": command, "output": str(exc)}


def observations(results):
    found = []
    pdfid = results.get("pdfid", {"status": "not_selected", "output": ""})
    if pdfid["status"] == "ok":
        for label in ("/JS", "/JavaScript", "/AA", "/OpenAction", "/Launch",
                      "/EmbeddedFile", "/XFA", "/AcroForm", "/Encrypt"):
            match = re.search(r"^\s*" + re.escape(label) + r"\s+(\d+)\s*$",
                              pdfid["output"], re.MULTILINE)
            if match and int(match.group(1)):
                found.append(f"pdfid found {label}: {match.group(1)}")
    if "qpdf" in results and results["qpdf"]["status"] not in ("ok", "unavailable"):
        found.append("qpdf reported an error; inspect its full output")
    clam = results.get("clamscan", {"output": ""})
    if clam.get("exit_code") == 1 or " FOUND" in clam["output"]:
        found.append("ClamAV reported a detection; inspect its full output")
    if "urls" in results and results["urls"].get("count", 0):
        found.append(f"Found {results['urls']['count']} literal URL(s); review without visiting")
    for name, result in results.items():
        if result["status"] in ("unavailable", "timeout", "error", "skipped"):
            found.append(f"{name}: {result['status']} (check incomplete)")
        elif result["status"] == "exit_error" and name not in ("qpdf", "clamscan"):
            found.append(f"{name}: tool returned an error (check incomplete)")
    if clam.get("exit_code") not in (None, 0, 1):
        found.append("ClamAV returned an error; its scan is inconclusive")
    if not found:
        found.append("No alert from selected checks; this does not prove the file is safe")
    return found


def make_pdf(path, data):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Preformatted, Spacer
    from xml.sax.saxutils import escape

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="AthenaTitle", parent=styles["Title"],
                              textColor=colors.HexColor("#a41520"), alignment=TA_CENTER))
    styles.add(ParagraphStyle(name="AthenaCode", fontName="Courier", fontSize=7,
                              leading=9, spaceAfter=8))
    doc = SimpleDocTemplate(str(path), pagesize=A4, leftMargin=42, rightMargin=42,
                            topMargin=42, bottomMargin=42)
    story = [Paragraph(escape(data.get("module", "Athena PDF Defense")), styles["AthenaTitle"]),
             Paragraph("a pdf active defense framework made by Bressh", styles["Normal"]),
             Spacer(1, 16)]
    for label, value in (("File", data["file"]), ("SHA-256", data["sha256"]),
                         ("Size", str(data["size_bytes"]) + " bytes"),
                         ("UTC", data["timestamp_utc"])):
        story.append(Paragraph(f"<b>{label}:</b> {escape(value)}", styles["Normal"]))
    story += [Spacer(1, 14), Paragraph("Observations", styles["Heading2"])]
    for item in data["observations"]:
        story.append(Paragraph("• " + escape(item), styles["Normal"]))
    story += [Spacer(1, 8), Paragraph("Static checks cannot establish sender identity, business legitimacy, or absence of exploits.", styles["Italic"])]
    for name, result in data["checks"].items():
        story.append(Paragraph(name + " — " + result["status"], styles["Heading2"]))
        lines = result["output"].splitlines() or ["(no output)"]
        if name == "pdftotext":
            lines = lines[:80]
            story.append(Paragraph("Text preview (up to 80 lines)", styles["Italic"]))
        for start in range(0, len(lines), 55):
            block = "\n".join(line[:100] for line in lines[start:start + 55])
            story.append(Preformatted(block, styles["AthenaCode"], maxLineLength=100))
    doc.build(story)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Interactive, local PDF analysis and unified reporting.")
    parser.add_argument("pdf", nargs="?", type=Path, help="PDF to inspect; prompted when omitted")
    parser.add_argument("-o", "--output-dir", type=Path, default=Path("athena-report"))
    parser.add_argument("--timeout", type=int, default=45, help="Seconds allowed per tool")
    parser.add_argument("--checks", help="Comma-separated check keys, or all/defense/hunting; skips menu")
    args = parser.parse_args(argv)
    print((RED if sys.stdout.isatty() and not os.environ.get("NO_COLOR") else "") + BANNER + RESET)
    if args.pdf is None:
        while True:
            try:
                raw = input("PDF path (or Q to quit): ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nCancelled")
                return 130
            if raw.lower() == "q":
                return 0
            pdf = Path(raw.strip("\"' ")).expanduser().resolve()
            if pdf.is_file():
                break
            print("File not found; try again.")
    else:
        pdf = args.pdf.expanduser().resolve()
        if not pdf.is_file():
            parser.error("Input file does not exist")
    if args.timeout < 1 or args.timeout > 600:
        parser.error("Timeout must be 1 to 600 seconds")
    if args.checks:
        requested = [item.strip().lower() for item in args.checks.split(",")]
        if requested == ["all"]:
            chosen = CHECKS
        elif requested in (["defense"], ["hunting"]):
            chosen = [c for c in CHECKS if c.category.lower() == requested[0]]
        else:
            unknown = set(requested) - {c.key for c in CHECKS}
            if unknown:
                parser.error("Unknown check(s): " + ", ".join(sorted(unknown)))
            chosen = [c for c in CHECKS if c.key in requested]
    else:
        try:
            chosen = select_checks()
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled")
            return 130
    if not chosen:
        print("No checks selected.")
        return 0
    out = args.output_dir.expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    with pdf.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    data = {"module": "Athena PDF Defense", "file": str(pdf), "size_bytes": pdf.stat().st_size,
            "sha256": digest.hexdigest(),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "selected_checks": [c.key for c in chosen], "checks": {}}
    for check in chosen:
        print(f"[+] {check.category}: {check.key}", flush=True)
        data["checks"][check.key] = (find_urls(pdf) if check.key == "urls"
                                     else run_check(check.key, check.build(pdf), args.timeout))
    data["observations"] = observations(data["checks"])
    base = "athena-" + digest.hexdigest()[:12]
    json_path = out / (base + ".json")
    json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        pdf_path = out / (base + ".pdf")
        make_pdf(pdf_path, data)
    except ImportError:
        print("[!] PDF report needs python3-reportlab: sudo apt install python3-reportlab", file=sys.stderr)
        return 2
    print(f"Report: {pdf_path}\nRaw results: {json_path}")
    for item in data["observations"]:
        print("- " + item)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

