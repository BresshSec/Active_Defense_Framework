import unittest
import zipfile
from email import policy
from email.parser import BytesParser
from pathlib import Path
from tempfile import TemporaryDirectory

from athena import cases, doctor
from athena.modules import archive_defense, batch_defense, email_defense, office_defense


class ModuleTests(unittest.TestCase):
    def test_email_sender_mismatch_and_attachment(self):
        raw = (b"From: Alice <alice@example.org>\n"
               b"Reply-To: Other <other@example.net>\n"
               b"To: Bob <bob@example.com>\n"
               b"Subject: Test\nMIME-Version: 1.0\n"
               b"Content-Type: multipart/mixed; boundary=x\n\n"
               b"--x\nContent-Type: text/plain\n\nVisit https://example.org/check\n"
               b"--x\nContent-Type: application/pdf\n"
               b"Content-Disposition: attachment; filename=sample.pdf\n\nPDF bytes\n--x--\n")
        message = BytesParser(policy=policy.default).parsebytes(raw)
        results, observations = email_defense.analyze(
            message, ["headers", "authentication", "attachments", "links", "body"])
        self.assertEqual(results["attachments"]["count"], 1)
        self.assertEqual(results["links"]["count"], 1)
        self.assertTrue(any("Reply-To" in note for note in observations))

    def test_archive_traversal_and_encryption_flags(self):
        with TemporaryDirectory() as directory:
            archive_path = Path(directory) / "sample.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("../escape.txt", "x")
                archive.writestr("safe.txt", "ok")
            with zipfile.ZipFile(archive_path) as archive:
                results, observations = archive_defense.analyze(
                    archive.infolist(), ["inventory", "paths", "encryption", "compression", "names"])
            self.assertEqual(results["paths"]["count"], 1)
            self.assertTrue(any("unsafe path" in note for note in observations))

    def test_ooxml_macro_and_external_relationship(self):
        with TemporaryDirectory() as directory:
            document = Path(directory) / "sample.docx"
            with zipfile.ZipFile(document, "w") as archive:
                archive.writestr("word/vbaProject.bin", b"test")
                archive.writestr("word/_rels/document.xml.rels",
                                 b'<Relationships><Relationship TargetMode="External" Target="https://example.org"/></Relationships>')
            result = office_defense.inspect_ooxml(document)
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["count"], 2)

    def test_batch_scans_eml_and_skips_symlink(self):
        with TemporaryDirectory() as directory:
            folder = Path(directory)
            message = folder / "message.eml"
            message.write_bytes(b"From: alice@example.org\nTo: bob@example.org\nSubject: Test\n\nHello")
            try:
                (folder / "linked.eml").symlink_to(message)
            except (OSError, NotImplementedError):
                pass
            files, omitted = batch_defense.collect_files(folder, recursive=False, max_files=10)
            self.assertEqual(files, [message])
            self.assertEqual(omitted, 0)
            result = batch_defense.scan_file(message, profile="quick", max_size=1024)
            self.assertEqual(result["status"], "ok")
            self.assertIn("attachments", result["checks"])

    def test_batch_excludes_previous_reports(self):
        with TemporaryDirectory() as directory:
            folder = Path(directory)
            reports = folder / "athena-report"
            reports.mkdir()
            (folder / "sample.txt").write_text("sample")
            (reports / "old.pdf").write_text("old report")
            files, omitted = batch_defense.collect_files(folder, True, 10, exclude=reports)
            self.assertEqual([p.name for p in files], ["sample.txt"])
            self.assertEqual(omitted, 0)

    def test_case_manifest_tracks_new_report(self):
        with TemporaryDirectory() as directory:
            case_id, case_dir = cases.create_case("file", Path(directory))
            report = case_dir / "sample.pdf"
            report.write_bytes(b"report")
            from datetime import datetime, timezone
            started = datetime.now(timezone.utc).isoformat()
            manifest = cases.save_manifest(case_id, case_dir, "file", started, case_dir, 0)
            self.assertTrue(manifest.is_file())
            self.assertIn(str(report), manifest.read_text(encoding="utf-8"))

    def test_doctor_reports_missing_signature_directory(self):
        with TemporaryDirectory() as directory:
            rows, status = doctor.inspect(Path(directory))
            self.assertTrue(rows)
            self.assertIn("no standard database files", status)


if __name__ == "__main__":
    unittest.main()

