#!/usr/bin/env python3
"""Create a reduced GhostLock report for manual review before sharing."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


PROOF_PATTERNS = {
    "same_pfn_capture": r"perf reclaim gate result verified=1 .*free=1 alloc=1",
    "credential_transition": (
        r"direct credential result uid=0 euid=0 gid=0 egid=0 .*selinux=1->0"
    ),
    "root_daemon": r"direct-root-summary root=1 id=1 su=1/",
}


class ReportError(RuntimeError):
    pass


def safe_state(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    allowed = (
        "uid",
        "context",
        "selinux",
        "fingerprint",
        "kernel_release",
        "slot",
        "abi",
        "payload_sha256",
    )
    return {key: value[key] for key in allowed if key in value}


def load_private_run(path: Path) -> tuple[dict[str, object], str]:
    directory = path if path.is_dir() else path.parent
    manifest_path = path if path.is_file() else directory / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ReportError(f"cannot read a GhostLock manifest: {exc}") from exc
    if not isinstance(manifest, dict):
        raise ReportError("manifest root must be a JSON object")
    try:
        run_log = (directory / "run.log").read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        run_log = ""
    return manifest, run_log


def redact(path: Path) -> dict[str, object]:
    manifest, run_log = load_private_run(path)
    kaslr = manifest.get("kaslr")
    anchors = kaslr.get("anchors", []) if isinstance(kaslr, dict) else []
    symbols = sorted(
        {
            anchor.get("symbol")
            for anchor in anchors
            if isinstance(anchor, dict) and isinstance(anchor.get("symbol"), str)
        }
    )
    proof = {
        name: re.search(pattern, run_log) is not None
        for name, pattern in PROOF_PATTERNS.items()
    }
    acceptance_ok = (
        manifest.get("acceptance_returncode") == 0
        and "uid=0(root)" in str(manifest.get("acceptance_output", ""))
    )
    return {
        "schema_version": 1,
        "tool": "ghostlock-aipin",
        "result": manifest.get("result", "unknown"),
        "mode": manifest.get("mode", "unknown"),
        "profile_id": manifest.get("profile_id"),
        "profile_manifest_sha256": manifest.get("profile_sha256"),
        "kernel_image_sha256": manifest.get("kernel_image_sha256"),
        "symbols_sha256": manifest.get("symbols_sha256"),
        "started_at": manifest.get("started_at"),
        "completed_at": manifest.get("completed_at"),
        "initial_state": safe_state(manifest.get("initial_state")),
        "final_state": safe_state(manifest.get("final_state")),
        "mm_geometry": manifest.get("mm_geometry"),
        "preflight": manifest.get("preflight"),
        "bugreport_binding": manifest.get("bugreport_binding"),
        "kaslr_anchor_count": len(anchors),
        "kaslr_anchor_symbols": symbols,
        "exploit_returncode": manifest.get("exploit_returncode"),
        "proof": proof,
        "acceptance_ok": acceptance_ok,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("private_run", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        rendered = json.dumps(redact(args.private_run), indent=2, sort_keys=True)
    except ReportError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.output:
        try:
            args.output.write_text(rendered + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"ERROR: cannot write reduced report: {exc}", file=sys.stderr)
            return 2
        print(
            f"Reduced report written to {args.output}; review it before sharing.",
            file=sys.stderr,
        )
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
