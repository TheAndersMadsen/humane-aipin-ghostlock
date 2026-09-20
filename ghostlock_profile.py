#!/usr/bin/env python3
"""Strict loader and matcher for evidence-backed GhostLock target profiles."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PROFILE_FILENAME = "profile.json"
SCHEMA_VERSION = 2
SHA256_RE = re.compile(r"[0-9a-f]{64}")
IDENTIFIER_RE = re.compile(r"[a-z0-9][a-z0-9._-]*")
SLOT_RE = re.compile(r"_[ab]")


class ProfileError(RuntimeError):
    """A profile is missing, malformed, ambiguous, or no longer hash-bound."""


def public_kernel_identity(kernel: str) -> str:
    """Remove the uname nodename while retaining compatibility fields."""
    fields = kernel.split(maxsplit=2)
    if len(fields) != 3 or fields[0] != "Linux":
        return "<unparseable uname>"
    return f"Linux <nodename> {fields[2]}"


@dataclass(frozen=True)
class AllocatorGeometry:
    object_size: int
    slab_size: int
    order: int
    objects_per_slab: int
    cpu_partial: int

    def validate(self) -> None:
        values = {
            "object_size": self.object_size,
            "slab_size": self.slab_size,
            "order": self.order,
            "objects_per_slab": self.objects_per_slab,
            "cpu_partial": self.cpu_partial,
        }
        if any(type(value) is not int or value <= 0 for value in values.values()):
            raise ProfileError("allocator geometry values must be positive integers")
        if self.object_size > self.slab_size:
            raise ProfileError("allocator object_size cannot exceed slab_size")
        if self.objects_per_slab * self.slab_size > 4096 << self.order:
            raise ProfileError("allocator geometry does not fit in the declared order")


@dataclass(frozen=True)
class TargetProfile:
    profile_id: str
    product: str
    project: str
    fingerprint: str
    kernel_release: str
    kernel_build_marker: str
    kernel_machine: str
    kernel_image_sha256: str
    accepted_slots: tuple[str, ...]
    accepted_abis: tuple[str, ...]
    symbols_path: Path
    symbols_sha256: str
    allocator_geometry: AllocatorGeometry
    manifest_path: Path
    manifest_sha256: str

    @staticmethod
    def _expected(values: tuple[str, ...]) -> str:
        if len(values) == 1:
            return repr(values[0])
        return "one of " + repr(values)

    def mismatches(
        self,
        *,
        fingerprint: str,
        kernel: str,
        kernel_release: str,
        slot: str,
        abi: str,
    ) -> tuple[str, ...]:
        mismatches: list[str] = []
        if fingerprint != self.fingerprint:
            mismatches.append(
                "firmware fingerprint: "
                f"expected {self.fingerprint!r}, observed {fingerprint!r}"
            )
        if kernel_release != self.kernel_release:
            mismatches.append(
                "kernel release: "
                f"expected {self.kernel_release!r}, observed {kernel_release!r}"
            )
        expected_kernel = re.compile(
            r"Linux \S+ "
            + re.escape(self.kernel_release)
            + " "
            + re.escape(self.kernel_build_marker)
            + " "
            + re.escape(self.kernel_machine)
        )
        if expected_kernel.fullmatch(kernel) is None:
            mismatches.append(
                "kernel identity: expected exact release/version/machine "
                f"{self.kernel_release!r}/{self.kernel_build_marker!r}/"
                f"{self.kernel_machine!r}, observed "
                f"{public_kernel_identity(kernel)!r}"
            )
        if slot not in self.accepted_slots:
            mismatches.append(
                "active slot: expected "
                f"{self._expected(self.accepted_slots)}, observed {slot!r}"
            )
        if abi not in self.accepted_abis:
            mismatches.append(
                f"ABI: expected {self._expected(self.accepted_abis)}, observed {abi!r}"
            )
        return tuple(mismatches)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ProfileError(f"cannot read profile-bound file {path}: {exc}") from exc
    return digest.hexdigest()


def verify_payload_profile_binding(
    path: Path,
    profile: TargetProfile,
    expected_payload_sha256: str | None = None,
) -> str:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise ProfileError(f"cannot read payload {path}: {exc}") from exc
    observed_sha256 = hashlib.sha256(payload).hexdigest()
    if (
        expected_payload_sha256 is not None
        and observed_sha256 != expected_payload_sha256.lower()
    ):
        raise ProfileError(
            "payload hash mismatch: "
            f"expected {expected_payload_sha256.lower()}, observed {observed_sha256}"
        )
    markers = {
        "profile manifest": profile.manifest_sha256,
        "kernel Image": profile.kernel_image_sha256,
        "symbols": profile.symbols_sha256,
    }
    missing = [
        label
        for label, marker in markers.items()
        if marker.encode("ascii") not in payload
    ]
    if missing:
        raise ProfileError(
            "payload is not bound to the selected profile; missing: "
            + ", ".join(missing)
        )
    return observed_sha256


def _require_object(value: Any, label: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProfileError(f"{label} must be a JSON object")
    actual = set(value)
    if actual != keys:
        missing = sorted(keys - actual)
        unknown = sorted(actual - keys)
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unknown:
            details.append("unknown " + ", ".join(unknown))
        raise ProfileError(f"{label} fields are invalid: {'; '.join(details)}")
    return value


def _require_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\0" in value or "\n" in value:
        raise ProfileError(f"{label} must be a non-empty single-line string")
    return value


def _require_sha256(value: Any, label: str) -> str:
    text = _require_text(value, label)
    if SHA256_RE.fullmatch(text) is None:
        raise ProfileError(f"{label} must be 64 lowercase hexadecimal characters")
    return text


def _require_string_list(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ProfileError(f"{label} must be a non-empty JSON array")
    items = tuple(_require_text(item, f"{label} item") for item in value)
    if len(items) != len(set(items)):
        raise ProfileError(f"{label} contains duplicate values")
    return items


def load_profile(path: Path) -> TargetProfile:
    manifest_path = path.resolve()
    try:
        raw = manifest_path.read_bytes()
    except OSError as exc:
        raise ProfileError(f"cannot read profile manifest {manifest_path}: {exc}") from exc
    try:
        data = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"cannot parse profile manifest {manifest_path}: {exc}") from exc

    fields = {
        "schema_version",
        "profile_id",
        "product",
        "project",
        "fingerprint",
        "kernel_release",
        "kernel_build_marker",
        "kernel_machine",
        "kernel_image_sha256",
        "accepted_slots",
        "accepted_abis",
        "symbols_file",
        "symbols_sha256",
        "allocator_geometry",
    }
    data = _require_object(data, f"profile {manifest_path}", fields)
    if type(data["schema_version"]) is not int or data["schema_version"] != SCHEMA_VERSION:
        raise ProfileError(
            f"unsupported schema_version {data['schema_version']!r}; expected {SCHEMA_VERSION}"
        )

    profile_id = _require_text(data["profile_id"], "profile_id")
    project = _require_text(data["project"], "project")
    if IDENTIFIER_RE.fullmatch(profile_id) is None:
        raise ProfileError("profile_id contains unsupported characters")
    if IDENTIFIER_RE.fullmatch(project) is None:
        raise ProfileError("project contains unsupported characters")

    accepted_slots = _require_string_list(data["accepted_slots"], "accepted_slots")
    if any(SLOT_RE.fullmatch(slot) is None for slot in accepted_slots):
        raise ProfileError("accepted_slots may contain only '_a' and '_b'")
    accepted_abis = _require_string_list(data["accepted_abis"], "accepted_abis")

    geometry_data = _require_object(
        data["allocator_geometry"],
        "allocator_geometry",
        {"object_size", "slab_size", "order", "objects_per_slab", "cpu_partial"},
    )
    geometry = AllocatorGeometry(**geometry_data)
    geometry.validate()

    symbols_name = _require_text(data["symbols_file"], "symbols_file")
    if symbols_name != "symbols.txt":
        raise ProfileError(
            "symbols_file must be 'symbols.txt' so build dependencies remain exact"
        )
    symbols_relative = Path(symbols_name)
    if symbols_relative.is_absolute() or ".." in symbols_relative.parts:
        raise ProfileError("symbols_file must stay inside the profile directory")
    symbols_path = (manifest_path.parent / symbols_relative).resolve()
    try:
        symbols_path.relative_to(manifest_path.parent)
    except ValueError as exc:
        raise ProfileError("symbols_file resolves outside the profile directory") from exc
    symbols_sha256 = _require_sha256(data["symbols_sha256"], "symbols_sha256")
    observed_symbols_sha256 = sha256_file(symbols_path)
    if observed_symbols_sha256 != symbols_sha256:
        raise ProfileError(
            "profile symbols hash mismatch: "
            f"expected {symbols_sha256}, observed {observed_symbols_sha256}"
        )

    return TargetProfile(
        profile_id=profile_id,
        product=_require_text(data["product"], "product"),
        project=project,
        fingerprint=_require_text(data["fingerprint"], "fingerprint"),
        kernel_release=_require_text(data["kernel_release"], "kernel_release"),
        kernel_build_marker=_require_text(
            data["kernel_build_marker"], "kernel_build_marker"
        ),
        kernel_machine=_require_text(data["kernel_machine"], "kernel_machine"),
        kernel_image_sha256=_require_sha256(
            data["kernel_image_sha256"], "kernel_image_sha256"
        ),
        accepted_slots=accepted_slots,
        accepted_abis=accepted_abis,
        symbols_path=symbols_path,
        symbols_sha256=symbols_sha256,
        allocator_geometry=geometry,
        manifest_path=manifest_path,
        manifest_sha256=hashlib.sha256(raw).hexdigest(),
    )


def load_profiles(root: Path) -> tuple[TargetProfile, ...]:
    manifests = sorted(root.glob(f"*/{PROFILE_FILENAME}"))
    if not manifests:
        raise ProfileError(f"no supported profiles found under {root}")
    profiles = tuple(load_profile(path) for path in manifests)

    ids: set[str] = set()
    projects: set[str] = set()
    for profile in profiles:
        if profile.profile_id in ids:
            raise ProfileError(f"duplicate profile_id {profile.profile_id!r}")
        ids.add(profile.profile_id)
        if profile.project in projects:
            raise ProfileError(
                f"multiple profiles target project {profile.project!r}; "
                "extend the existing profile for another validated slot, or create "
                "a new target project for a different kernel Image"
            )
        projects.add(profile.project)

    for index, left in enumerate(profiles):
        for right in profiles[index + 1 :]:
            same_kernel_identity = (
                left.fingerprint == right.fingerprint
                and left.kernel_release == right.kernel_release
                and left.kernel_build_marker == right.kernel_build_marker
                and left.kernel_machine == right.kernel_machine
            )
            if (
                same_kernel_identity
                and set(left.accepted_slots) & set(right.accepted_slots)
                and set(left.accepted_abis) & set(right.accepted_abis)
            ):
                raise ProfileError(
                    "profiles have an ambiguous live identity: "
                    f"{left.profile_id!r} and {right.profile_id!r}"
                )
    return profiles


def profile_by_id(
    profiles: tuple[TargetProfile, ...], profile_id: str
) -> TargetProfile:
    matches = [profile for profile in profiles if profile.profile_id == profile_id]
    if len(matches) != 1:
        available = ", ".join(profile.profile_id for profile in profiles)
        raise ProfileError(
            f"unsupported profile_id {profile_id!r}; available profiles: {available}"
        )
    return matches[0]


def matching_profile(
    profiles: tuple[TargetProfile, ...],
    *,
    fingerprint: str,
    kernel: str,
    kernel_release: str,
    slot: str,
    abi: str,
) -> TargetProfile | None:
    matches = [
        profile
        for profile in profiles
        if not profile.mismatches(
            fingerprint=fingerprint,
            kernel=kernel,
            kernel_release=kernel_release,
            slot=slot,
            abi=abi,
        )
    ]
    if len(matches) > 1:
        ids = ", ".join(profile.profile_id for profile in matches)
        raise ProfileError(f"device matches multiple profiles: {ids}")
    return matches[0] if matches else None


def nearest_profile(
    profiles: tuple[TargetProfile, ...],
    *,
    fingerprint: str,
    kernel: str,
    kernel_release: str,
    slot: str,
    abi: str,
) -> tuple[TargetProfile, tuple[str, ...]]:
    ranked = [
        (
            profile,
            profile.mismatches(
                fingerprint=fingerprint,
                kernel=kernel,
                kernel_release=kernel_release,
                slot=slot,
                abi=abi,
            ),
        )
        for profile in profiles
    ]
    return min(ranked, key=lambda item: (len(item[1]), item[0].profile_id))
