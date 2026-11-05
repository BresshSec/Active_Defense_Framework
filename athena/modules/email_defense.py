"""Offline EML triage. No attachments are extracted or opened."""

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from pathlib import Path

from .pdf_defense import make_pdf

MAX_SIZE = 50 * 1024 * 1024
URL_RE = re.compile(r"https?://[^\s<>\"']{4,300}", re.IGNORECASE)
CHECKS = [
    ("headers", "Defense", "Sender, recipient and routing headers"),
    ("authentication", "Defense", "SPF, DKIM and DMARC claims in headers"),
    ("attachments", "Defense", "Attachment names, types, sizes and SHA-256"),
    ("links", "Hunting", "Literal links in text and HTML"),
    ("body", "Hunting", "Plain text body preview"),
]


def choose():
    selected = {key for key, category, _ in CHECKS if category == "Defense"}
    while True:
        print("\nEmail checks (* = selected):")
        for index, (key, category, description) in enumerate(CHECKS, 1):
            mark = "*" if key in selected else " "
            print(f" {index}. [{mark}] {category:7} {key:14} {description}")
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


def analyze(message, selected):
    results = {}
    observations = []
    if "headers" in selected:
        names = ("From", "Reply-To", "To", "Cc", "Date", "Subject", "Message-ID", "Return-Path", "Received")
        lines = [f"{name}: {value}" for name in names for value in message.get_all(name, [])]
        results["headers"] = {"status": "ok", "output": "\n".join(lines) or "No matching headers"}
        sender = getaddresses(message.get_all("From", []))
        reply = getaddresses(message.get_all("Reply-To", []))
        if sender and reply and sender[0][1].lower() != reply[0][1].lower():
            observations.append("From and Reply-To addresses differ; verify the sender independently")
    if "authentication" in selected:
        names = ("Authentication-Results", "Received-SPF", "DKIM-Signature", "ARC-Authentication-Results")
        lines = [f"{name}: {value}" for name in names for value in message.get_all(name, [])]
        results["authentication"] = {"status": "ok", "output": "\n".join(lines) or "No authentication results present"}
        observations.append("Authentication headers are claims in this file; verify against the trusted mail server")
    if "attachments" in selected:
        lines = []
        count = 0
        for part in message.walk():
            if part.is_multipart():
                continue
            name = part.get_filename()
            if not name and part.get_content_disposition() != "attachment":
                continue
            count += 1
            if count > 200:
                lines.append("Attachment limit reached; remaining parts omitted")
                break
            payload = part.get_payload(decode=True) or b""
            lines.append(f"Name: {name or '(unnamed)'} | MIME: {part.get_content_type()} | Size: {len(payload)} | SHA-256: {hashlib.sha256(payload).hexdigest()}")
            if name and (name.lower().endswith((".exe", ".js", ".vbs", ".lnk", ".scr")) or name.count(".") >= 2):
                observations.append(f"Review attachment filename: {name}")
        results["attachments"] = {"status": "ok", "output": "\n".join(lines) or "No attachments", "count": count}
    body_lines = []
    links = set()
    if "links" in selected or "body" in selected:
        for part in message.walk():
            if part.is_multipart() or part.get_content_disposition() == "attachment":
                continue
            if part.get_content_type() not in ("text/plain", "text/html"):
                continue
            try:
                content = part.get_content()
            except (LookupError, UnicodeError, ValueError):
                continue
            if not isinstance(content, str):
                continue
            if part.get_content_type() == "text/plain":
                body_lines.append(content[:10000])
            links.update(URL_RE.findall(content[:200000]))
    if "links" in selected:
        results["links"] = {"status": "ok", "output": "\n".join(sorted(links)[:200]) or "No literal links found",
                            "count": len(links), "note": "Links are not visited"}
        if links:
            observations.append(f"Found {len(links)} literal link(s); review without visiting")
    if "body" in selected:
        results["body"] = {"status": "ok", "output": "\n".join(body_lines)[:20000] or "No plain text body"}
    if not observations:
        observations.append("No alert from selected checks; sender identity is not established")
    return results, observations


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline EML analysis")
    parser.add_argument("eml", nargs="?", type=Path)
    parser.add_argument("-o", "--output-dir", type=Path, default=Path("athena-report"))
    parser.add_argument("--checks", help="Comma-separated keys, or all/defense/hunting")
    args = parser.parse_args(argv)
    if args.eml is None:
        try:
            raw = input("EML path (or Q to quit): ").strip()
        except (EOFError, KeyboardInterrupt):
            return 130
        if raw.lower() == "q":
            return 0
        path = Path(raw.strip("\"' ")).expanduser().resolve()
    else:
        path = args.eml.expanduser().resolve()
    if not path.is_file():
        parser.error("EML file not found")
    if path.stat().st_size > MAX_SIZE:
        parser.error("EML exceeds 50 MB limit")
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
    raw = path.read_bytes()
    message = BytesParser(policy=policy.default).parsebytes(raw)
    results, observations = analyze(message, selected)
    data = {"module": "Athena Email Defense", "file": str(path), "size_bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "selected_checks": selected, "observations": observations, "checks": results}
    out = args.output_dir.expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    stem = "athena-email-" + data["sha256"][:12]
    json_path = out / (stem + ".json")
    json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        pdf_path = out / (stem + ".pdf")
        make_pdf(pdf_path, data)
    except ImportError:
        print("Install python3-reportlab to generate PDF reports.", file=sys.stderr)
        return 2
    print(f"Report: {pdf_path}\nRaw results: {json_path}")
    return 0

