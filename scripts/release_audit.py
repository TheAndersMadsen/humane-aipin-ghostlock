#!/usr/bin/env python3
"""Fail if a candidate release tree contains private or generated material."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_PATH_PARTS = {
    "artifacts",
    "evidence",
    "__pycache__",
}
FORBIDDEN_NAMES = {
    "PIN.zip",
    "adbkey",
    "adbkey.pub",
}
FORBIDDEN_SUFFIXES = {
    ".img",
    ".raw",
    ".zip",
}
CONTENT_PATTERNS = {
    "personal home path": re.compile(
        rb"(?:/Users|/home)/[A-Za-z0-9._-]+/"
    ),
    "ADB private key": re.compile(rb"BEGIN (?:OPENSSH |RSA )?PRIVATE KEY"),
    "GitHub token": re.compile(rb"gh[opsu]_[A-Za-z0-9]{20,}"),
    "AI Pin serial": re.compile(rb"1H4MPA[0-9A-Z]{5,}"),
}


def candidate_paths() -> list[Path]:
    output = subprocess.check_output(
        [
            "git",
            "-C",
            str(ROOT),
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ]
    )
    return [ROOT / item.decode() for item in output.split(b"\0") if item]


def main() -> int:
    failures: list[str] = []
    for path in candidate_paths():
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if any(part in FORBIDDEN_PATH_PARTS for part in relative.parts):
            failures.append(f"forbidden path: {relative}")
            continue
        if path.name in FORBIDDEN_NAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
            failures.append(f"forbidden release file: {relative}")
            continue
        data = path.read_bytes()
        if len(data) > 1024 * 1024:
            failures.append(f"file exceeds 1 MiB: {relative}")
        if b"\0" in data[:8192]:
            failures.append(f"binary file is tracked: {relative}")
            continue
        for label, pattern in CONTENT_PATTERNS.items():
            if pattern.search(data):
                failures.append(f"{label} found in {relative}")

    if failures:
        print("release audit failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("release audit passed: no private paths, credentials, serials, or binaries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
