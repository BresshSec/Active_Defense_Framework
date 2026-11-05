import unittest
import zipfile
from email import policy
from email.parser import BytesParser
from pathlib import Path
from tempfile import TemporaryDirectory

from athena.modules import archive_defense, email_defense, office_defense


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


if __name__ == "__main__":
    unittest.main()

