# Athena PDF Defense

An interactive, local PDF analysis framework for Kali Linux. It offers selectable **Defense** and **Hunting** checks, prints a red terminal banner, and combines selected results in one PDF report plus a JSON evidence file.

## Install

Copy `athena-pdf-defense.py` and `install-kali.sh` into the same directory, then run:

```bash
bash install-kali.sh
```

The installer uses Kali's package repositories and installs Python, ReportLab, `file`, Poppler tools, `qpdf`, `pdfid`, `pdf-parser`, ClamAV, and ExifTool. Kali removed `peepdf` from its rolling repositories because it depends on Python 2, so the framework uses `pdf-parser` for object inspection. ClamAV signatures need to be current before relying on its result.

## Interactive use

```bash
python3 athena-pdf-defense.py
```

Enter the PDF path when prompted. The menu initially selects Defense checks. Type check numbers to toggle them, `a` for all, `d` for Defense, `h` for Hunting, `r` to clear, or press Enter to run. The report is written to `athena-report/`.

## Optional command line use

```bash
python3 athena-pdf-defense.py ~/analisi-pdf/example.pdf --checks all
python3 athena-pdf-defense.py ~/analisi-pdf/example.pdf --checks pdfid,qpdf,urls -o ~/reports
```

Defense: real file type, PDF metadata, suspicious PDF keywords, structural validation, antivirus signatures. Hunting: text, objects, embedded images, metadata, and literal URL strings. The URL scan never visits addresses and may miss compressed or encoded URLs. All checks are static; none executes PDF actions or opens attachments. Each external tool has a timeout. Missing tools and failed checks are recorded in the report.

The report may contain confidential text from the PDF. Store and share it accordingly. No automated result proves that a file is safe or that the sender and transaction are legitimate.

