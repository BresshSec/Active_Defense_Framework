# Athena Defense

An interactive, local defense framework for Kali Linux. Launch it by typing `Athenadef`. On a Kali desktop with Xfce, it opens a new maximized terminal window. On a headless system it runs in the current terminal. The blue module manager offers six modules: PDF, File, Email, Archive, Office, and Batch Defense. The PDF module retains its red banner. Each module combines selected results in one PDF report plus a JSON evidence file.

## Install

From the cloned repository, run:

```bash
bash install-kali.sh
```

The installer uses Kali's package repositories and installs Python, ReportLab, `file`, Poppler tools, `qpdf`, `pdfid`, `pdf-parser`, ClamAV, ExifTool, Xfce Terminal, and `oletools`. On amd64/arm64 it also attempts to install optional `binwalk3`. It creates `/usr/local/bin/Athenadef`, pointing to this checkout. Keep the repository in place after installation. Kali removed `peepdf` from its rolling repositories because it depends on Python 2, so PDF Defense uses `pdf-parser` for object inspection. ClamAV signatures need to be current before relying on its result.

## Interactive use

```bash
Athenadef
```

Choose module 1 (PDF Defense), 2 (File Defense), 3 (Email Defense, for `.eml`), 4 (Archive Defense, for `.zip`), 5 (Office Defense, for Word, Excel and PowerPoint documents), or 6 (Batch Defense, for folders). For single-file modules, enter a file path and select checks. Type check numbers to toggle them, `a` for all, `d` for Defense, `h` for Hunting, or press Enter to run. PDF and File modules also support `r` to clear. Batch Defense offers quick and deep profiles, a recursive option, and size/count limits. Reports are written to `athena-report/` in the current directory. Use `Athenadef --inline` to stay in your current terminal.

## Optional command line use

```bash
python3 athena-pdf-defense.py ~/analisi-pdf/example.pdf --checks all
Athenadef pdf ~/analisi-pdf/example.pdf --checks pdfid,qpdf,urls -o ~/reports
Athenadef file ~/Downloads/sample.zip --checks all
Athenadef email ~/Downloads/message.eml --checks all
Athenadef archive ~/Downloads/sample.zip --checks all
Athenadef office ~/Downloads/document.docx --checks all
Athenadef batch ~/Downloads/samples --recursive --profile deep --max-files 100
```

PDF Defense: real file type, PDF metadata, suspicious PDF keywords, structural validation, antivirus signatures. PDF Hunting: text, objects, attachments, signatures, embedded images, metadata, and literal URL strings. File Defense: type, MIME, antivirus signatures, metadata. File Hunting: embedded signatures (`binwalk3`), entropy, printable strings, literal URLs, and ZIP member listing without extraction. Email Defense: headers, sender/reply-to mismatch, authentication header claims, attachment names/types/sizes/hashes, and literal links. Archive Defense: ZIP members, path traversal, symlinks, encryption flags, compression ratios, and suspicious names. Office Defense: `oleid`, `mraptor`, `olevba`, `msodde`, and OOXML macro/external link/embedding checks. Batch Defense: bounded, optionally recursive folder triage with one combined report. Its deep profile adds ClamAV and more format-specific checks; quick is the default. URL scans never visit addresses and may miss compressed or encoded URLs. All checks are static; none executes samples or opens attachments. Each external tool has a timeout. Missing tools and failed checks are recorded in the report.

The report may contain confidential text from the PDF. Store and share it accordingly. No automated result proves that a file is safe or that the sender and transaction are legitimate.

