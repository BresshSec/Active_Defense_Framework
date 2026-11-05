"""Read-only installation and signature health checks."""

import importlib.util
import shutil
from datetime import datetime, timezone
from pathlib import Path

CORE = ("python3", "file", "pdfinfo", "pdfid", "qpdf", "pdf-parser",
        "clamscan", "exiftool", "oleid", "olevba", "yara")
OPTIONAL = ("binwalk3", "xfce4-terminal", "pdfdetach", "pdfsig", "pdftotext",
            "pdfimages", "mraptor", "msodde")
SIGNATURE_DIR = Path("/var/lib/clamav")


def inspect(signature_dir=SIGNATURE_DIR):
    rows = [(name, "available" if shutil.which(name) else "missing") for name in CORE + OPTIONAL]
    rows.append(("reportlab", "available" if importlib.util.find_spec("reportlab") else "missing"))
    signatures = [signature_dir / name for name in ("main.cvd", "main.cld", "daily.cvd", "daily.cld", "bytecode.cvd", "bytecode.cld")]
    present = [path for path in signatures if path.is_file()]
    if present:
        newest = max(path.stat().st_mtime for path in present)
        age_days = (datetime.now(timezone.utc).timestamp() - newest) / 86400
        status = f"{len(present)} database file(s); newest updated {age_days:.1f} day(s) ago"
        if age_days > 7:
            status += " (check freshness)"
    else:
        status = "no standard database files found; check freshclam configuration"
    return rows, status


def main(argv=None):
    rows, status = inspect()
    print("Athena Defense — installation health\n")
    for name, state in rows:
        print(f"  {name:18} {state}")
    print(f"\nClamAV signatures: {status}")
    print("\nMissing tools are recorded as unavailable in reports.")
    return 0

