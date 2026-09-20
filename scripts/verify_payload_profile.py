#!/usr/bin/env python3
"""Verify that a built payload embeds an exact GhostLock profile identity."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ghostlock_profile import (  # noqa: E402
    ProfileError,
    load_profile,
    verify_payload_profile_binding,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--payload", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        profile = load_profile(args.profile)
        digest = verify_payload_profile_binding(args.payload, profile)
    except ProfileError as exc:
        parser.error(str(exc))
    print(
        f"payload profile binding passed: {profile.profile_id} "
        f"manifest={profile.manifest_sha256} payload={digest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
