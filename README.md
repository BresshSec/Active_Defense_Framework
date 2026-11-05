# Athena Defense

An interactive, local defense framework for Kali Linux. Launch it by typing `Athenadef`. The blue module manager offers PDF Defense and File Defense. The PDF module retains its red banner. Each module combines selected results in one PDF report plus a JSON evidence file.

## Install

From the cloned repository, run:

```bash
bash install-kali.sh
```

The installer uses Kali's package repositories and installs Python, ReportLab, `file`, Poppler tools, `qpdf`, `pdfid`, `pdf-parser`, ClamAV, and ExifTool. It creates `/usr/local/bin/Athenadef`, pointing to this checkout. Keep the repository in place after installation. Kali removed `peepdf` from its rolling repositories because it depends on Python 2, so PDF Defense uses `pdf-parser` for object inspection. ClamAV signatures need to be current before relying on its result.

## Interactive use

```bash
Athenadef
```

Choose module 1 (PDF Defense) or 2 (File Defense), then enter a file path. Each module initially selects Defense checks. Type check numbers to toggle them, `a` for all, `d` for Defense, `h` for Hunting, `r` to clear, or press Enter to run. Reports are written to `athena-report/` in the current directory.

## Optional command line use

```bash
python3 athena-pdf-defense.py ~/analisi-pdf/example.pdf --checks all
Athenadef pdf ~/analisi-pdf/example.pdf --checks pdfid,qpdf,urls -o ~/reports
Athenadef file ~/Downloads/sample.zip --checks all
```

PDF Defense: real file type, PDF metadata, suspicious PDF keywords, structural validation, antivirus signatures. PDF Hunting: text, objects, embedded images, metadata, and literal URL strings. File Defense: type, MIME, antivirus signatures, metadata. File Hunting: entropy, printable strings, literal URLs, and ZIP member listing without extraction. URL scans never visit addresses and may miss compressed or encoded URLs. All checks are static; none executes samples or opens attachments. Each external tool has a timeout. Missing tools and failed checks are recorded in the report.

The report may contain confidential text from the PDF. Store and share it accordingly. No automated result proves that a file is safe or that the sender and transaction are legitimate.

