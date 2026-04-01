#!/usr/bin/env python3

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import textwrap
from datetime import datetime
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable


MAX_FILE_PREVIEW = 256 * 1024
MAX_TAR_MEMBER_PREVIEW = 128 * 1024
SUSPICIOUS_EXTENSIONS = {
    ".apk",
    ".appimage",
    ".bat",
    ".bin",
    ".cmd",
    ".com",
    ".dll",
    ".dmg",
    ".exe",
    ".iso",
    ".jar",
    ".msi",
    ".pkg",
    ".ps1",
    ".scr",
}
SUSPICIOUS_FILENAMES = {
    "authorized_keys",
    "id_rsa",
    "id_dsa",
    "id_ed25519",
    ".bashrc",
    ".zshrc",
    ".profile",
    ".bash_profile",
    "ld.so.preload",
}
TEXT_SCAN_EXTENSIONS = {
    "",
    ".bash",
    ".bat",
    ".cjs",
    ".cmd",
    ".conf",
    ".desktop",
    ".env",
    ".fish",
    ".js",
    ".ksh",
    ".mjs",
    ".pl",
    ".ps1",
    ".py",
    ".rb",
    ".service",
    ".sh",
    ".timer",
    ".ts",
    ".tsx",
    ".yaml",
    ".yml",
    ".zsh",
}
TEXT_REGEX_PATTERNS = [
    ("reverse-shell", "high", re.compile(r"\b(?:bash|sh|zsh)\b.*?/dev/tcp/", re.IGNORECASE)),
    ("netcat-exec", "high", re.compile(r"\bnc\s+-e\b", re.IGNORECASE)),
    ("curl-pipe-shell", "high", re.compile(r"\bcurl\b[^\n|]{0,500}\|\s*(?:sh|bash)\b", re.IGNORECASE)),
    ("wget-pipe-shell", "high", re.compile(r"\bwget\b[^\n|]{0,500}\|\s*(?:sh|bash)\b", re.IGNORECASE)),
    (
        "powershell-iex",
        "high",
        re.compile(
            r"(?:\biex\b|\binvoke-expression\b).{0,400}(?:downloadstring|downloadfile|invoke-webrequest)|"
            r"(?:downloadstring|downloadfile|invoke-webrequest).{0,400}(?:\biex\b|\binvoke-expression\b)",
            re.IGNORECASE,
        ),
    ),
    (
        "base64-exec",
        "high",
        re.compile(
            r"frombase64string.{0,300}(?:\biex\b|\binvoke-expression\b|\bexec\b|bash\s+-c)|"
            r"(?:\biex\b|\binvoke-expression\b|\bexec\b|bash\s+-c).{0,300}frombase64string",
            re.IGNORECASE,
        ),
    ),
    ("crypto-miner", "medium", re.compile(r"stratum\+tcp://|\bxmrig\b|--rig-id\b", re.IGNORECASE)),
    ("persistence-cron", "medium", re.compile(r"/etc/cron\.[^ ]*|\bcrontab\s+-", re.IGNORECASE)),
    (
        "ssh-persistence",
        "medium",
        re.compile(r"authorized_keys.{0,200}(ssh-rsa|ssh-ed25519)|echo.{0,200}authorized_keys", re.IGNORECASE),
    ),
    ("ld-preload", "medium", re.compile(r"ld_preload|ld\.so\.preload", re.IGNORECASE)),
    (
        "launch-agent",
        "medium",
        re.compile(r"launchagents.{0,200}(load|plist)|launchctl\s+load", re.IGNORECASE),
    ),
]
DOCKER_PATH_PATTERNS = [
    ("cron-dropper", "medium", "/etc/cron."),
    ("ssh-persistence", "medium", "/root/.ssh/authorized_keys"),
    ("loader-hijack", "high", "/etc/ld.so.preload"),
    ("tmp-executable", "medium", "/tmp/"),
    ("tmp-executable", "medium", "/var/tmp/"),
]
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")


@dataclass
class Finding:
    severity: str
    scope: str
    target: str
    rule: str
    detail: str


@dataclass
class ScanProgress:
    phase: str
    message: str
    current: int | None = None
    total: int | None = None
    done: bool = False


ProgressCallback = Callable[[ScanProgress], None]


def run_command(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(cmd)}\n{completed.stderr.strip()}"
        )
    return completed


class TerminalProgressRenderer:
    def __init__(self, *, enabled: bool, disable_color: bool) -> None:
        self.enabled = enabled and sys.stderr.isatty()
        self.use_color = color_enabled(disable_color)
        self.frames = ["|", "/", "-", "\\"]
        self.frame_index = 0
        self.last_width = 0
        self.started = False

    def _phase_label(self, phase: str) -> str:
        labels = {
            "prepare": "Prepare",
            "pull": "Pull",
            "inventory": "Inventory",
            "scan": "Heuristic",
            "history": "History",
            "export": "Export",
            "filesystem": "Filesystem",
            "clamav": "ClamAV",
            "report": "Report",
            "done": "Done",
        }
        return labels.get(phase, phase.title())

    def _progress_meter(self, progress: ScanProgress) -> str:
        if progress.current is None or progress.total in {None, 0}:
            return ""
        width = 18
        ratio = min(max(progress.current / progress.total, 0.0), 1.0)
        filled = int(width * ratio)
        bar = "█" * filled + "░" * (width - filled)
        return f" [{bar}] {progress.current}/{progress.total}"

    def update(self, progress: ScanProgress) -> None:
        if not self.enabled:
            return
        self.started = True
        frame = "✓" if progress.done else self.frames[self.frame_index % len(self.frames)]
        self.frame_index += 1
        phase = self._phase_label(progress.phase)
        phase_text = colorize(f"[{phase}]", fg="cyan", bold=True, enabled=self.use_color)
        line = f"{frame} {phase_text} {progress.message}{self._progress_meter(progress)}"
        max_width = max(40, terminal_width() - 1)
        if visible_length(line) > max_width:
            plain = ANSI_ESCAPE_RE.sub("", line)
            plain = plain[: max_width - 3] + "..."
            line = plain
        padding = max(0, self.last_width - visible_length(line))
        sys.stderr.write("\r" + line + (" " * padding))
        sys.stderr.flush()
        self.last_width = visible_length(line)
        if progress.done:
            sys.stderr.write("\n")
            sys.stderr.flush()
            self.last_width = 0
            self.started = False

    def finish(self, message: str = "Scan complete") -> None:
        if not self.enabled:
            return
        self.update(ScanProgress(phase="done", message=message, done=True))


def emit_progress(progress: ProgressCallback | None, phase: str, message: str, current: int | None = None, total: int | None = None, done: bool = False) -> None:
    if progress is None:
        return
    progress(ScanProgress(phase=phase, message=message, current=current, total=total, done=done))


def is_binary_blob(data: bytes) -> bool:
    return b"\x00" in data


def make_finding(severity: str, scope: str, target: str, rule: str, detail: str) -> Finding:
    return Finding(severity=severity, scope=scope, target=target, rule=rule, detail=detail)


def scan_text_patterns(preview: str, scope: str, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in preview.splitlines():
        compact_line = " ".join(line.split())
        for rule, severity, regex in TEXT_REGEX_PATTERNS:
            if regex.search(compact_line):
                findings.append(
                    make_finding(
                        severity,
                        scope,
                        target,
                        rule,
                        f"Matched suspicious command pattern in line: {compact_line[:180]}",
                    )
                )
    return findings


def should_scan_text_content(path: Path, executable: bool) -> bool:
    if path.name in {"Dockerfile", "Containerfile"}:
        return True
    return executable or path.suffix.lower() in TEXT_SCAN_EXTENSIONS


def should_scan_tar_text_content(member: tarfile.TarInfo) -> bool:
    name = PurePosixPath(member.name).name
    suffix = PurePosixPath(member.name).suffix.lower()
    executable = bool(member.mode & 0o111)
    if name in {"Dockerfile", "Containerfile"}:
        return True
    if suffix in TEXT_SCAN_EXTENSIONS:
        return True
    if executable and not suffix:
        return True
    if any(part in {"bin", "sbin", "init.d", "profile.d"} for part in PurePosixPath(member.name).parts):
        return True
    return False


def load_ignore_patterns(repo_path: Path) -> list[str]:
    ignore_file = repo_path / ".pullguardignore"
    if not ignore_file.exists():
        return []
    patterns: list[str] = []
    for raw_line in ignore_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        patterns.append(line)
    return patterns


def should_ignore(relpath: str, ignore_patterns: list[str]) -> bool:
    for pattern in ignore_patterns:
        if fnmatch.fnmatch(relpath, pattern):
            return True
        if pattern.endswith("/") and relpath.startswith(pattern):
            return True
    return False


def scan_path_metadata(path: Path, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    relpath = str(path.relative_to(root))
    try:
        info = path.lstat()
    except OSError as exc:
        return [make_finding("low", "repo", relpath, "read-error", str(exc))]

    if stat.S_ISLNK(info.st_mode):
        target = os.readlink(path)
        resolved_target = (path.parent / target).resolve(strict=False)
        if os.path.isabs(target) or not resolved_target.is_relative_to(root.resolve()):
            findings.append(
                make_finding(
                    "high",
                    "repo",
                    relpath,
                    "symlink-escape",
                    f"Symlink points outside the repository: {target}",
                )
            )
        return findings

    if path.suffix.lower() in SUSPICIOUS_EXTENSIONS:
        findings.append(
            make_finding(
                "medium",
                "repo",
                relpath,
                "suspicious-extension",
                f"File extension {path.suffix.lower()} deserves extra review.",
            )
        )

    if path.name in SUSPICIOUS_FILENAMES:
        findings.append(
            make_finding(
                "medium",
                "repo",
                relpath,
                "suspicious-filename",
                f"Sensitive or persistence-related filename detected: {path.name}",
            )
        )

    if info.st_mode & stat.S_IXUSR and path.suffix.lower() not in {".py", ".sh", ".pl", ".rb"}:
        findings.append(
            make_finding(
                "low",
                "repo",
                relpath,
                "unexpected-executable",
                "Executable bit is set on a non-standard file type.",
            )
        )

    if info.st_size > 50 * 1024 * 1024:
        findings.append(
            make_finding(
                "low",
                "repo",
                relpath,
                "large-file",
                f"Large file detected ({info.st_size} bytes). Review if unexpected.",
            )
        )

    return findings


def scan_file_content(path: Path, root: Path) -> list[Finding]:
    relpath = str(path.relative_to(root))
    executable = os.access(path, os.X_OK)
    if not should_scan_text_content(path, executable):
        return []
    try:
        with path.open("rb") as handle:
            blob = handle.read(MAX_FILE_PREVIEW)
    except OSError as exc:
        return [make_finding("low", "repo", relpath, "read-error", str(exc))]

    if is_binary_blob(blob):
        return []

    text = blob.decode("utf-8", errors="ignore")
    return scan_text_patterns(text, "repo", relpath)


def run_clamscan(target_path: Path, scope: str, progress: ProgressCallback | None = None) -> list[Finding]:
    if shutil.which("clamscan") is None:
        return []

    emit_progress(progress, "clamav", f"Running ClamAV on {target_path}")
    completed = run_command(
        ["clamscan", "-r", "--infected", "--no-summary", str(target_path)],
        check=False,
    )
    findings: list[Finding] = []
    for line in completed.stdout.splitlines():
        if line.endswith("FOUND") and ": " in line:
            filename, signature = line.split(": ", 1)
            findings.append(
                make_finding(
                    "high",
                    scope,
                    filename,
                    "clamscan",
                    f"ClamAV flagged this item: {signature}",
                )
            )
    emit_progress(progress, "clamav", f"Finished ClamAV on {target_path}", done=True)
    return findings


def repository_scan_paths(repo_path: Path) -> list[Path]:
    return [
        path
        for path in repo_path.rglob("*")
        if ".git" not in path.parts and not path.is_dir()
    ]


def scan_repository(repo_path: Path, progress: ProgressCallback | None = None) -> list[Finding]:
    repo_path = repo_path.resolve()
    ignore_patterns = load_ignore_patterns(repo_path)
    emit_progress(progress, "inventory", f"Collecting files from {repo_path}")
    paths = repository_scan_paths(repo_path)
    emit_progress(progress, "inventory", f"Collected {len(paths)} files", done=True)
    findings: list[Finding] = []
    total_paths = max(1, len(paths))
    emit_progress(progress, "scan", "Scanning repository contents", current=0, total=total_paths)
    for index, path in enumerate(paths, start=1):
        relpath = str(path.relative_to(repo_path))
        if should_ignore(relpath, ignore_patterns):
            if index == len(paths) or index % 25 == 0:
                emit_progress(progress, "scan", f"Scanning repository contents: {relpath}", current=index, total=total_paths)
            continue
        findings.extend(scan_path_metadata(path, repo_path))
        if path.is_file():
            findings.extend(scan_file_content(path, repo_path))
        if index == len(paths) or index % 25 == 0:
            emit_progress(progress, "scan", f"Scanning repository contents: {relpath}", current=index, total=total_paths)
    emit_progress(progress, "scan", "Repository heuristic scan finished", current=total_paths, total=total_paths, done=True)
    findings.extend(run_clamscan(repo_path, "repo", progress=progress))
    return deduplicate_findings(findings)


def tar_member_preview(tar: tarfile.TarFile, member: tarfile.TarInfo) -> str:
    extracted = tar.extractfile(member)
    if extracted is None:
        return ""
    blob = extracted.read(MAX_TAR_MEMBER_PREVIEW)
    if is_binary_blob(blob):
        return ""
    return blob.decode("utf-8", errors="ignore")


def scan_tar_member(member: tarfile.TarInfo, tar: tarfile.TarFile) -> list[Finding]:
    findings: list[Finding] = []
    target = str(PurePosixPath("/") / member.name)
    lower_target = target.lower()

    if member.mode & 0o4000:
        findings.append(
            make_finding(
                "medium",
                "image",
                target,
                "setuid-file",
                "Image contains a setuid file. Confirm it is expected.",
            )
        )

    suffix = PurePosixPath(member.name).suffix.lower()
    if suffix in SUSPICIOUS_EXTENSIONS:
        findings.append(
            make_finding(
                "medium",
                "image",
                target,
                "suspicious-extension",
                f"Image contains a file with extension {suffix}.",
            )
        )

    if PurePosixPath(member.name).name in SUSPICIOUS_FILENAMES:
        findings.append(
            make_finding(
                "medium",
                "image",
                target,
                "suspicious-filename",
                f"Image contains a persistence-related filename: {PurePosixPath(member.name).name}",
            )
        )

    for rule, severity, marker in DOCKER_PATH_PATTERNS:
        if marker in lower_target:
            findings.append(
                make_finding(severity, "image", target, rule, f"Matched suspicious image path marker: {marker}")
            )

    if member.isfile() and should_scan_tar_text_content(member):
        findings.extend(scan_text_patterns(tar_member_preview(tar, member), "image", target))

    return findings


def scan_docker_history(image: str, progress: ProgressCallback | None = None) -> list[Finding]:
    findings: list[Finding] = []
    emit_progress(progress, "history", f"Inspecting image history: {image}")
    completed = run_command(
        ["docker", "history", "--no-trunc", "--format", "{{.CreatedBy}}", image],
        check=False,
    )
    if completed.returncode != 0:
        return [
            make_finding(
                "low",
                "image",
                image,
                "history-unavailable",
                completed.stderr.strip() or "Unable to inspect docker history.",
            )
        ]
    for line in completed.stdout.splitlines():
        findings.extend(scan_text_patterns(line, "image-history", image))
    emit_progress(progress, "history", f"Finished image history inspection: {image}", done=True)
    return findings


def export_docker_image(image: str, output_tar: Path, progress: ProgressCallback | None = None) -> None:
    container_id = ""
    try:
        emit_progress(progress, "export", f"Creating temporary container for {image}")
        container_id = run_command(["docker", "create", image]).stdout.strip()
        emit_progress(progress, "export", f"Exporting image filesystem: {image}")
        run_command(["docker", "export", "-o", str(output_tar), container_id])
    finally:
        if container_id:
            run_command(["docker", "rm", "-f", container_id], check=False)
    emit_progress(progress, "export", f"Image export ready: {output_tar.name}", done=True)


def scan_image_filesystem(image: str, progress: ProgressCallback | None = None) -> list[Finding]:
    findings: list[Finding] = []
    with tempfile.TemporaryDirectory(prefix="pull-guard-") as tempdir:
        tempdir_path = Path(tempdir)
        export_tar = tempdir_path / "image.tar"
        export_docker_image(image, export_tar, progress=progress)
        with tarfile.open(export_tar) as tar:
            members = tar.getmembers()
            total_members = max(1, len(members))
            emit_progress(progress, "filesystem", f"Scanning exported filesystem for {image}", current=0, total=total_members)
            for index, member in enumerate(members, start=1):
                findings.extend(scan_tar_member(member, tar))
                if index == len(members) or index % 50 == 0:
                    emit_progress(
                        progress,
                        "filesystem",
                        f"Inspecting filesystem entries: {PurePosixPath(member.name).name or member.name}",
                        current=index,
                        total=total_members,
                    )
            emit_progress(progress, "filesystem", f"Finished filesystem scan for {image}", current=total_members, total=total_members, done=True)
        if shutil.which("clamscan") is not None:
            extracted_root = tempdir_path / "fs"
            extracted_root.mkdir()
            with tarfile.open(export_tar) as tar:
                safe_members = [member for member in tar.getmembers() if member.isdir() or member.isfile()]
                tar.extractall(extracted_root, members=safe_members, filter="data")
            findings.extend(run_clamscan(extracted_root, "image", progress=progress))
    return findings


def scan_docker_image(image: str, progress: ProgressCallback | None = None) -> list[Finding]:
    findings = scan_docker_history(image, progress=progress)
    findings.extend(scan_image_filesystem(image, progress=progress))
    return deduplicate_findings(findings)


def deduplicate_findings(findings: Iterable[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str, str, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (
            finding.severity,
            finding.scope,
            finding.target,
            finding.rule,
            finding.detail,
        )
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    unique.sort(key=lambda item: (-SEVERITY_RANK[item.severity], item.target, item.rule))
    return unique


def terminal_width() -> int:
    width = shutil.get_terminal_size((100, 24)).columns
    return max(80, min(width, 120))


def color_enabled(disable_color: bool) -> bool:
    if disable_color:
        return False
    return sys.stdout.isatty() and os.environ.get("TERM", "dumb") != "dumb"


def colorize(
    text: str,
    *,
    fg: str | None = None,
    bg: str | None = None,
    bold: bool = False,
    enabled: bool = False,
) -> str:
    if not enabled:
        return text
    color_map = {
        "red": "31",
        "green": "32",
        "yellow": "33",
        "blue": "34",
        "magenta": "35",
        "cyan": "36",
        "white": "37",
    }
    bg_map = {
        "red": "41",
        "green": "42",
        "yellow": "43",
        "blue": "44",
        "magenta": "45",
        "cyan": "46",
        "white": "47",
    }
    codes: list[str] = []
    if bold:
        codes.append("1")
    if fg:
        codes.append(color_map[fg])
    if bg:
        codes.append(bg_map[bg])
    if not codes:
        return text
    return f"\033[{';'.join(codes)}m{text}\033[0m"


def visible_length(text: str) -> int:
    return len(ANSI_ESCAPE_RE.sub("", text))


def pad_visible(text: str, width: int) -> str:
    return text + (" " * max(0, width - visible_length(text)))


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    return {
        "high": sum(1 for item in findings if item.severity == "high"),
        "medium": sum(1 for item in findings if item.severity == "medium"),
        "low": sum(1 for item in findings if item.severity == "low"),
    }


def severity_badge(severity: str, use_color: bool) -> str:
    label = f" {severity.upper()} "
    if severity == "high":
        return colorize(label, fg="white", bg="red", bold=True, enabled=use_color)
    if severity == "medium":
        return colorize(label, fg="white", bg="yellow", bold=True, enabled=use_color)
    return colorize(label, fg="white", bg="blue", bold=True, enabled=use_color)


def status_text(findings: list[Finding], use_color: bool) -> str:
    if findings:
        return colorize(" REVIEW REQUIRED ", fg="white", bg="red", bold=True, enabled=use_color)
    return colorize(" CLEAN ", fg="white", bg="green", bold=True, enabled=use_color)


def status_line(findings: list[Finding], use_color: bool) -> str:
    counts = severity_counts(findings)
    if findings:
        return (
            f"{status_text(findings, use_color)}  "
            f"{severity_badge('high', use_color)} {counts['high']}  "
            f"{severity_badge('medium', use_color)} {counts['medium']}  "
            f"{severity_badge('low', use_color)} {counts['low']}"
        )
    return f"{status_text(findings, use_color)}  No suspicious indicators were found."


def generated_at_text() -> str:
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def findings_by_rule(findings: list[Finding]) -> list[tuple[str, int, str]]:
    grouped: dict[str, tuple[int, str]] = {}
    for finding in findings:
        count, highest = grouped.get(finding.rule, (0, "low"))
        highest = finding.severity if SEVERITY_RANK[finding.severity] > SEVERITY_RANK[highest] else highest
        grouped[finding.rule] = (count + 1, highest)
    ranked = [
        (rule, count, highest)
        for rule, (count, highest) in grouped.items()
    ]
    ranked.sort(key=lambda item: (-SEVERITY_RANK[item[2]], -item[1], item[0]))
    return ranked


def format_box(title: str, lines: list[str], width: int) -> str:
    inner_width = width - 4
    top = f"┌─ {title} " + ("─" * max(0, width - len(title) - 5)) + "┐"
    rendered = [top]
    for line in lines:
        wrapped = (
            textwrap.wrap(
                line,
                width=inner_width,
                replace_whitespace=False,
                drop_whitespace=False,
            )
            or [""]
        )
        for chunk in wrapped:
            rendered.append(f"│ {pad_visible(chunk, inner_width)} │")
    rendered.append("└" + ("─" * (width - 2)) + "┘")
    return "\n".join(rendered)


def grouped_findings(findings: list[Finding]) -> dict[str, list[Finding]]:
    return {
        "high": [item for item in findings if item.severity == "high"],
        "medium": [item for item in findings if item.severity == "medium"],
        "low": [item for item in findings if item.severity == "low"],
    }


def format_findings_lines(findings: list[Finding], use_color: bool, max_details: int) -> list[str]:
    if not findings:
        return ["No suspicious indicators were found."]

    lines: list[str] = []
    finding_index = 1
    remaining_detail_slots = max(0, max_details)
    for severity in ("high", "medium", "low"):
        severity_items = grouped_findings(findings)[severity]
        if not severity_items:
            continue
        lines.append(
            f"{severity_badge(severity, use_color)} {severity.upper()} RISK  count={len(severity_items)}"
        )
        shown_items = severity_items[: max(0, remaining_detail_slots)]
        for item in shown_items:
            lines.append(f"  {finding_index:02d}. rule={item.rule}  scope={item.scope}")
            lines.append(f"      target: {item.target}")
            lines.append(f"      detail: {item.detail}")
            finding_index += 1
            if item is not shown_items[-1]:
                lines.append("")
        remaining_detail_slots -= len(shown_items)
        hidden_count = len(severity_items) - len(shown_items)
        if hidden_count > 0:
            lines.append(f"  ... {hidden_count} more {severity.upper()} finding(s) collapsed into summary below")
        if severity != "low":
            lines.append("")
    return lines


def collapsed_summary_lines(findings: list[Finding], max_details: int, use_color: bool) -> list[str]:
    detail_limit = max(0, max_details)
    hidden_findings = findings[detail_limit:]
    if not hidden_findings:
        return ["All findings are expanded above."]
    lines = [f"Showing first {detail_limit} findings. Remaining {len(hidden_findings)} finding(s) are summarized here."]
    for rule, count, highest in findings_by_rule(hidden_findings)[:8]:
        lines.append(f"{severity_badge(highest, use_color)} rule={rule}  count={count}  highest={highest.upper()}")
    return lines


def top_risk_lines(findings: list[Finding], use_color: bool) -> list[str]:
    if not findings:
        return ["No high-priority rule clusters detected."]
    lines: list[str] = []
    for index, (rule, count, highest) in enumerate(findings_by_rule(findings)[:5], start=1):
        score = (SEVERITY_RANK[highest] * 10) + count
        lines.append(
            f"{index}. {severity_badge(highest, use_color)} rule={rule}  score={score}  count={count}  highest={highest.upper()}"
        )
    return lines


def recommendation_lines(findings: list[Finding]) -> list[str]:
    counts = severity_counts(findings)
    if not findings:
        return [
            "No immediate action required.",
            "Keep ClamAV signatures updated with scripts/update_clamav_db.sh.",
            "Use --json if you want to export results to other tools.",
        ]

    lines: list[str] = []
    if counts["high"]:
        lines.append("Review and quarantine HIGH findings before executing pulled code or images.")
    if counts["medium"]:
        lines.append("Inspect MEDIUM findings for persistence hooks, suspicious extensions, or image paths.")
    if counts["low"]:
        lines.append("LOW findings are informational, but still worth checking if they are unexpected.")
    if not lines:
        lines.append("Review the findings list before executing pulled code or images.")
    lines.append("Re-run with --json if you want machine-readable output for logging or CI.")
    return lines


def format_terminal_report(
    findings: list[Finding],
    *,
    mode_label: str,
    target_label: str,
    disable_color: bool = False,
    max_details: int = 8,
    extra_header_lines: list[str] | None = None,
) -> str:
    max_details = max(0, max_details)
    width = terminal_width()
    use_color = color_enabled(disable_color)
    counts = severity_counts(findings)
    clamav_path = shutil.which("clamscan")
    header_lines = [
        f"Status   : {status_line(findings, use_color)}",
        f"Mode     : {mode_label}",
        f"Target   : {target_label}",
        f"Generated: {generated_at_text()}",
        f"ClamAV   : {'ENABLED' if clamav_path else 'DISABLED'}" + (f" ({clamav_path})" if clamav_path else ""),
    ]
    if extra_header_lines:
        header_lines.extend(extra_header_lines)
    summary_lines = [
        (
            f"Risk profile: {severity_badge('high', use_color)} {counts['high']}    "
            f"{severity_badge('medium', use_color)} {counts['medium']}    "
            f"{severity_badge('low', use_color)} {counts['low']}"
        ),
        f"Total findings: {len(findings)}",
    ]
    sections = [
        format_box("Pull Guard Terminal Dashboard", header_lines, width),
        format_box("Severity Summary", summary_lines, width),
        format_box("Findings", format_findings_lines(findings, use_color, max_details), width),
        format_box("Collapsed Summary", collapsed_summary_lines(findings, max_details, use_color), width),
        format_box("Top Risks", top_risk_lines(findings, use_color), width),
        format_box("Recommendations", recommendation_lines(findings), width),
    ]
    return "\n\n".join(sections)


def render_plain_report(findings: list[Finding]) -> None:
    if not findings:
        print("No suspicious indicators were found.")
        return
    for finding in findings:
        print(f"[{finding.severity.upper()}] {finding.scope} {finding.target} :: {finding.rule} :: {finding.detail}")
    counts = severity_counts(findings)
    print(f"\nSummary: {counts['high']} high, {counts['medium']} medium, {counts['low']} low findings.")


def render_report(
    findings: list[Finding],
    *,
    as_json: bool,
    plain: bool,
    mode_label: str,
    target_label: str,
    disable_color: bool,
    max_details: int,
    extra_header_lines: list[str] | None = None,
) -> int:
    if as_json:
        print(json.dumps([asdict(item) for item in findings], ensure_ascii=False, indent=2))
    elif plain:
        render_plain_report(findings)
    else:
        print(
            format_terminal_report(
                findings,
                mode_label=mode_label,
                target_label=target_label,
                disable_color=disable_color,
                max_details=max_details,
                extra_header_lines=extra_header_lines,
            )
        )
    return 1 if findings else 0


def progress_renderer_from_args(args: argparse.Namespace) -> TerminalProgressRenderer:
    enabled = not args.json and not args.plain and not args.no_progress
    return TerminalProgressRenderer(enabled=enabled, disable_color=args.no_color)


def pull_status_header_line(status: str, detail: str) -> str:
    return f"Git Pull  : {status} ({detail})"


def handle_repo_scan(args: argparse.Namespace) -> int:
    repo_path = Path(args.path).resolve()
    progress = progress_renderer_from_args(args)
    findings = scan_repository(repo_path, progress=progress.update if progress.enabled else None)
    if progress.enabled:
        progress.finish("Repository scan complete")
    return render_report(
        findings,
        as_json=args.json,
        plain=args.plain,
        mode_label="Repository Scan",
        target_label=str(repo_path),
        disable_color=args.no_color,
        max_details=args.max_findings,
    )


def handle_image_scan(args: argparse.Namespace) -> int:
    progress = progress_renderer_from_args(args)
    findings = scan_docker_image(args.image, progress=progress.update if progress.enabled else None)
    if progress.enabled:
        progress.finish("Docker image scan complete")
    return render_report(
        findings,
        as_json=args.json,
        plain=args.plain,
        mode_label="Docker Image Scan",
        target_label=args.image,
        disable_color=args.no_color,
        max_details=args.max_findings,
    )


def handle_git_pull(args: argparse.Namespace) -> int:
    repo_path = Path(args.repo).resolve()
    progress = progress_renderer_from_args(args)
    pull_header_line: list[str] = []
    if args.scan_only:
        pull_header_line.append(pull_status_header_line("SKIPPED", "local scan only"))
    else:
        if progress.enabled:
            progress.update(ScanProgress(phase="pull", message=f"Running git pull in {repo_path}"))
        pull_cmd = ["git", "-C", str(repo_path), "pull"]
        if args.remote:
            pull_cmd.append(args.remote)
        if args.branch:
            pull_cmd.append(args.branch)
        completed = run_command(pull_cmd, check=False)
        sys.stdout.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        if completed.returncode == 0:
            pull_header_line.append(pull_status_header_line("OK", "repository updated before scan"))
            if progress.enabled:
                progress.update(ScanProgress(phase="pull", message="git pull completed", done=True))
        else:
            pull_header_line.append(
                pull_status_header_line(
                    "FAILED",
                    "remote unavailable, scanned existing local checkout instead",
                )
            )
            if progress.enabled:
                progress.update(
                    ScanProgress(
                        phase="pull",
                        message="git pull failed, continuing with local scan",
                        done=True,
                    )
                )
            if args.strict_pull:
                return completed.returncode
    findings = scan_repository(repo_path, progress=progress.update if progress.enabled else None)
    if progress.enabled:
        progress.finish("Git pull scan complete")
    return render_report(
        findings,
        as_json=args.json,
        plain=args.plain,
        mode_label="Git Pull + Scan",
        target_label=str(repo_path),
        disable_color=args.no_color,
        max_details=args.max_findings,
        extra_header_lines=pull_header_line,
    )


def handle_docker_pull(args: argparse.Namespace) -> int:
    completed = run_command(["docker", "pull", args.image], check=False)
    sys.stdout.write(completed.stdout)
    sys.stderr.write(completed.stderr)
    if completed.returncode != 0:
        return completed.returncode
    progress = progress_renderer_from_args(args)
    findings = scan_docker_image(args.image, progress=progress.update if progress.enabled else None)
    if progress.enabled:
        progress.finish("Docker pull scan complete")
    return render_report(
        findings,
        as_json=args.json,
        plain=args.plain,
        mode_label="Docker Pull + Scan",
        target_label=args.image,
        disable_color=args.no_color,
        max_details=args.max_findings,
    )


def add_output_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="Render findings as JSON.")
    parser.add_argument("--plain", action="store_true", help="Use the legacy plain-text report.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color in the terminal report.")
    parser.add_argument("--no-progress", action="store_true", help="Disable the live progress indicator.")
    parser.add_argument(
        "--max-findings",
        type=int,
        default=8,
        help="Maximum number of detailed findings to expand before collapsing the rest into a summary.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan a git working tree or a docker image for suspicious malware indicators."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    repo_scan = subparsers.add_parser("scan-repo", help="Scan a local repository path.")
    repo_scan.add_argument("path", nargs="?", default=".", help="Repository path to scan. Defaults to current directory.")
    add_output_flags(repo_scan)
    repo_scan.set_defaults(func=handle_repo_scan)

    image_scan = subparsers.add_parser("scan-image", help="Scan a docker image already present locally.")
    image_scan.add_argument("image", help="Docker image reference.")
    add_output_flags(image_scan)
    image_scan.set_defaults(func=handle_image_scan)

    git_pull = subparsers.add_parser("git-pull-scan", help="Run git pull and then scan the repo.")
    git_pull.add_argument("repo", nargs="?", default=".", help="Repository path. Defaults to current directory.")
    git_pull.add_argument("--remote", help="Remote name, for example origin.")
    git_pull.add_argument("--branch", help="Branch name, for example main.")
    git_pull.add_argument("--scan-only", action="store_true", help="Skip git pull and only scan the local repository contents.")
    git_pull.add_argument("--strict-pull", action="store_true", help="Abort if git pull fails instead of continuing with a local scan.")
    add_output_flags(git_pull)
    git_pull.set_defaults(func=handle_git_pull)

    docker_pull = subparsers.add_parser("docker-pull-scan", help="Run docker pull and then scan the image.")
    docker_pull.add_argument("image", help="Docker image reference.")
    add_output_flags(docker_pull)
    docker_pull.set_defaults(func=handle_docker_pull)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except Exception as exc:  # pragma: no cover - CLI safety net
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
