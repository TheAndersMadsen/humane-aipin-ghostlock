#!/usr/bin/env python3
"""Friendly, fail-closed launcher for the Humane AI Pin GhostLock PoC."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ghostlock_profile import (  # noqa: E402
    ProfileError,
    TargetProfile,
    load_profiles,
    matching_profile,
    nearest_profile,
    profile_by_id,
)


SOURCE = ROOT / "source"
PROFILES_ROOT = ROOT / "profiles"
PINNED_NDK_VERSION = "28.2.13676358"
RUNNER = ROOT / "runner/ghostlock_prod_runner.py"
REDACTOR = ROOT / "tools/redact_report.py"
REMOTE_PAYLOAD = "/data/local/tmp/ghostlock-aipin.so"
REMOTE_SU = "/data/local/tmp/su"


class GhostLockError(RuntimeError):
    pass


@dataclass(frozen=True)
class DeviceInfo:
    serial: str
    fingerprint: str
    kernel: str
    kernel_release: str
    slot: str
    abi: str
    uid: str
    context: str
    selinux: str
    battery_level: int | None
    powered: bool | None

    @property
    def clean_shell(self) -> bool:
        return (
            self.uid == "2000"
            and self.context == "u:r:shell:s0"
            and self.selinux == "Enforcing"
        )


def run(
    command: list[str],
    *,
    timeout: int = 30,
    check: bool = True,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GhostLockError(f"cannot run {command[0]!r}: {exc}") from exc
    if check and result.returncode != 0:
        output = result.stdout.strip()
        raise GhostLockError(
            f"command failed ({result.returncode}): {' '.join(command)}"
            + (f"\n{output}" if output else "")
        )
    return result


def adb(serial: str, *args: str, timeout: int = 30, check: bool = True):
    return run(["adb", "-s", serial, *args], timeout=timeout, check=check)


def shell(serial: str, command: str, *, timeout: int = 30, check: bool = True):
    return adb(serial, "shell", command, timeout=timeout, check=check)


def shell_value(serial: str, command: str) -> str:
    return shell(serial, command).stdout.replace("\r", "").strip()


def require_command(name: str) -> None:
    if shutil.which(name) is None:
        raise GhostLockError(f"required command is missing: {name}")


def connected_devices() -> list[str]:
    require_command("adb")
    result = run(["adb", "devices"])
    devices: list[str] = []
    for line in result.stdout.replace("\r", "").splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 2 and fields[1] == "device":
            devices.append(fields[0])
    return devices


def select_serial(requested: str | None) -> str:
    devices = connected_devices()
    if requested:
        if requested not in devices:
            found = ", ".join(devices) or "none"
            raise GhostLockError(
                f"device {requested!r} is not ready; connected devices: {found}"
            )
        return requested
    if len(devices) != 1:
        found = ", ".join(devices) or "none"
        raise GhostLockError(
            "connect exactly one authorized AI Pin or pass --serial; "
            f"ready devices: {found}"
        )
    return devices[0]


def parse_battery(text: str) -> tuple[int | None, bool | None]:
    level_match = re.search(r"(?m)^\s*level:\s*(\d+)\s*$", text)
    level = int(level_match.group(1)) if level_match else None
    power_matches = re.findall(
        r"(?mi)^\s*(?:AC|USB|Wireless) powered:\s*(true|false)\s*$", text
    )
    powered = any(value.lower() == "true" for value in power_matches) if power_matches else None
    return level, powered


def inspect_device(serial: str) -> DeviceInfo:
    battery = shell(serial, "dumpsys battery", check=False).stdout
    level, powered = parse_battery(battery)
    return DeviceInfo(
        serial=serial,
        fingerprint=shell_value(serial, "getprop ro.build.fingerprint"),
        kernel=shell_value(serial, "uname -a"),
        kernel_release=shell_value(serial, "uname -r"),
        slot=shell_value(serial, "getprop ro.boot.slot_suffix"),
        abi=shell_value(serial, "getprop ro.product.cpu.abi"),
        uid=shell_value(serial, "id -u"),
        context=shell_value(serial, "id -Z"),
        selinux=shell_value(serial, "getenforce"),
        battery_level=level,
        powered=powered,
    )


def evaluate_device(
    info: DeviceInfo, profiles: tuple[TargetProfile, ...]
) -> tuple[TargetProfile | None, tuple[str, ...]]:
    profile = matching_profile(
        profiles,
        fingerprint=info.fingerprint,
        kernel=info.kernel,
        kernel_release=info.kernel_release,
        slot=info.slot,
        abi=info.abi,
    )
    if profile is not None:
        return profile, ()
    _candidate, mismatches = nearest_profile(
        profiles,
        fingerprint=info.fingerprint,
        kernel=info.kernel,
        kernel_release=info.kernel_release,
        slot=info.slot,
        abi=info.abi,
    )
    return None, mismatches


def print_device(
    info: DeviceInfo,
    profile: TargetProfile | None,
    mismatches: tuple[str, ...],
) -> None:
    battery = "unknown" if info.battery_level is None else f"{info.battery_level}%"
    power = "unknown" if info.powered is None else ("connected" if info.powered else "not connected")
    print(f"Device:      {info.serial}")
    print(f"Firmware:    {info.fingerprint}")
    print(f"Kernel:      {info.kernel}")
    print(f"Release:     {info.kernel_release}")
    print(f"Slot:        {info.slot}")
    print(f"ABI:         {info.abi}")
    print(f"Shell:       uid={info.uid} {info.context}")
    print(f"SELinux:     {info.selinux}")
    print(f"Battery:     {battery}, external power {power}")
    print(f"Profile:     {profile.profile_id if profile else 'UNSUPPORTED'}")
    for mismatch in mismatches:
        print(f"Mismatch:    {mismatch}")


def find_ndk(explicit: str | None) -> Path | None:
    candidates: list[Path] = []
    for value in (
        explicit,
        os.environ.get("NDK_ROOT"),
        os.environ.get("ANDROID_NDK_HOME"),
        os.environ.get("ANDROID_NDK_ROOT"),
    ):
        if value:
            candidates.append(Path(value).expanduser())
    candidates.extend(
        (
            Path.home() / "Library/Android/sdk/ndk" / PINNED_NDK_VERSION,
            Path.home() / "Android/Sdk/ndk" / PINNED_NDK_VERSION,
        )
    )
    for candidate in candidates:
        properties = candidate / "source.properties"
        if not (candidate / "toolchains/llvm/prebuilt").is_dir():
            continue
        try:
            metadata = properties.read_text(encoding="utf-8")
        except OSError:
            continue
        if re.search(
            rf"(?m)^Pkg\.Revision\s*=\s*{re.escape(PINNED_NDK_VERSION)}\s*$",
            metadata,
        ):
            return candidate.resolve()
    return None


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def payload_path(profile: TargetProfile) -> Path:
    return SOURCE / "build" / profile.project / "bin" / "preload.so"


def build_payload(profile: TargetProfile, ndk_arg: str | None) -> tuple[Path, str]:
    require_command("make")
    ndk = find_ndk(ndk_arg)
    if ndk is None:
        raise GhostLockError(
            f"Android NDK {PINNED_NDK_VERSION} was not found. Install that exact "
            "side-by-side revision or pass --ndk /path/to/it."
        )
    environment = os.environ.copy()
    environment["NDK_ROOT"] = str(ndk)
    print(f"Building with Android NDK: {ndk}")
    result = run(
        [
            "make",
            "-C",
            str(SOURCE),
            "clean",
            "preload",
            f"PROJECT={profile.project}",
            f"PROFILE_MANIFEST={profile.manifest_path}",
        ],
        timeout=300,
        env=environment,
    )
    print(result.stdout, end="")
    payload = payload_path(profile)
    if not payload.is_file():
        raise GhostLockError(f"build succeeded without producing {payload}")
    digest = sha256(payload)
    print(f"Payload:     {payload}")
    print(f"SHA-256:     {digest}")
    return payload, digest


def require_target(
    info: DeviceInfo,
    profiles: tuple[TargetProfile, ...],
    *,
    min_battery: int,
) -> TargetProfile:
    profile, mismatches = evaluate_device(info, profiles)
    if profile is None:
        details = "; ".join(mismatches)
        raise GhostLockError(
            "unsupported device or firmware; no evidence-backed profile matches. "
            f"Mismatch: {details}"
        )
    if not info.clean_shell:
        raise GhostLockError(
            "root attempts require a clean uid-2000 shell, u:r:shell:s0, and SELinux "
            "Enforcing. Reboot first if this boot was already exploited."
        )
    if min_battery > 0:
        if info.battery_level is None or info.powered is None:
            raise GhostLockError(
                "battery or power state is unavailable; use --min-battery 0 only after "
                "you have independently confirmed stable external power"
            )
        if info.battery_level < min_battery:
            raise GhostLockError(
                f"battery is {info.battery_level}%; at least {min_battery}% is required"
            )
        if not info.powered:
            raise GhostLockError("external power is not connected")
    return profile


def confirm_risk(info: DeviceInfo, assume_yes: bool) -> None:
    if assume_yes:
        return
    if not sys.stdin.isatty():
        raise GhostLockError("non-interactive runs require --yes")
    print()
    print("This kernel exploit can crash, reboot, or hard-hang the Pin.")
    print("A hard hang may require unplugging the Pin and waiting for its battery to drain.")
    print("Root lasts only until reboot.")
    print("It does not flash a partition, unlock the bootloader, or create reboot persistence.")
    phrase = f"ROOT {info.serial}"
    answer = input(f"Type {phrase!r} to continue: ").strip()
    if answer != phrase:
        raise GhostLockError("confirmation did not match the connected device")


def push_payload(serial: str, payload: Path, digest: str) -> None:
    print(f"Pushing payload to {serial} …")
    result = adb(serial, "push", str(payload), REMOTE_PAYLOAD, timeout=120)
    print(result.stdout, end="")
    shell(serial, f"chmod 0644 {REMOTE_PAYLOAD}")
    remote_fields = shell_value(
        serial, f"toybox sha256sum {REMOTE_PAYLOAD} 2>/dev/null"
    ).split()
    if not remote_fields or remote_fields[0].lower() != digest:
        raise GhostLockError("device payload hash does not match the local build")
    print(f"Device hash: {remote_fields[0].lower()} (verified)")


def evidence_path(requested: str | None) -> Path:
    if requested:
        path = Path(requested).expanduser().resolve()
    else:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
        path = Path("/private/tmp") / f"ghostlock-aipin-{stamp}"
    if path.exists():
        raise GhostLockError(f"evidence directory already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def verify_root(serial: str) -> bool:
    result = shell(serial, f"{REMOTE_SU} -c id", timeout=30, check=False)
    output = result.stdout.replace("\r", "").strip()
    enforcing = shell(serial, f"{REMOTE_SU} -c getenforce", check=False).stdout.strip()
    btime = shell_value(serial, "sed -n 's/^btime //p' /proc/stat | head -n 1")
    uptime = shell_value(serial, "cut -d ' ' -f 1 /proc/uptime")
    print(output or "su did not return output")
    print(f"SELinux: {enforcing or 'unknown'}")
    print(f"Boot epoch: {btime}; uptime: {uptime}s")
    return result.returncode == 0 and "uid=0(root)" in output and enforcing == "Permissive"


def command_check(args: argparse.Namespace) -> int:
    profiles = load_profiles(PROFILES_ROOT)
    serial = select_serial(args.serial)
    info = inspect_device(serial)
    profile, mismatches = evaluate_device(info, profiles)
    print_device(info, profile, mismatches)
    ndk = find_ndk(args.ndk)
    print(
        f"Android NDK: {ndk if ndk else f'{PINNED_NDK_VERSION} not found'}"
    )
    if profile is None:
        return 2
    if not info.clean_shell:
        print("Status:      supported, but this boot is not clean for a new exploit run")
        return 1
    if ndk is None:
        print("Status:      device supported, but the pinned Android NDK is missing")
        return 1
    print("Status:      ready for a guarded run")
    return 0


def command_build(args: argparse.Namespace) -> int:
    profiles = load_profiles(PROFILES_ROOT)
    if args.profile:
        profile = profile_by_id(profiles, args.profile)
    elif len(profiles) == 1:
        profile = profiles[0]
    else:
        available = ", ".join(item.profile_id for item in profiles)
        raise GhostLockError(
            f"multiple profiles are available; pass --profile from: {available}"
        )
    build_payload(profile, args.ndk)
    return 0


def command_verify(args: argparse.Namespace) -> int:
    serial = select_serial(args.serial)
    return 0 if verify_root(serial) else 2


def command_report(args: argparse.Namespace) -> int:
    command = [sys.executable, str(REDACTOR), str(args.private_run)]
    if args.output:
        command.extend(("--output", str(args.output)))
    result = subprocess.run(command, cwd=ROOT, check=False)
    return result.returncode


def command_run(args: argparse.Namespace) -> int:
    profiles = load_profiles(PROFILES_ROOT)
    serial = select_serial(args.serial)
    info = inspect_device(serial)
    selected, mismatches = evaluate_device(info, profiles)
    print_device(info, selected, mismatches)
    profile = require_target(info, profiles, min_battery=args.min_battery)
    confirm_risk(info, args.yes)

    payload = payload_path(profile)
    digest = sha256(payload) if args.no_build and payload.is_file() else None
    if args.no_build and digest is None:
        raise GhostLockError(f"--no-build requested but {payload} does not exist")
    if digest is None:
        payload, digest = build_payload(profile, args.ndk)
    push_payload(serial, payload, digest)

    output = evidence_path(args.output_dir)
    command = [
        sys.executable,
        str(RUNNER),
        "--serial",
        serial,
        "--profile-id",
        profile.profile_id,
        "--profile-sha256",
        profile.manifest_sha256,
        "--payload-sha256",
        digest,
        "--remote-payload",
        REMOTE_PAYLOAD,
        "--remote-su",
        REMOTE_SU,
        "--output-dir",
        str(output),
        "--execute",
    ]
    if args.retain_bugreport:
        command.append("--retain-bugreport")
    print(f"Private log: {output}")
    print("Starting guarded exploit chain; this usually takes several minutes …")
    result = subprocess.run(command, cwd=ROOT, check=False)
    if result.returncode != 0:
        raise GhostLockError(
            f"runner failed closed with exit {result.returncode}; inspect {output}"
        )
    print("\nIndependent fresh-shell verification:")
    if not verify_root(serial):
        raise GhostLockError("runner completed but independent root verification failed")
    print(f"\nSuccess. Root is active on {serial} until the next reboot.")
    print(f"Run './ghostlock verify --serial {serial}' at any time to re-check it.")
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="ghostlock",
        description=(
            "Build, diagnose, and run the device-specific GhostLock PoC for the "
            "Humane AI Pin retail 45.20 firmware."
        ),
    )
    root.add_argument("--version", action="version", version="ghostlock-aipin 0.1.0")
    sub = root.add_subparsers(dest="command", required=True)

    check = sub.add_parser(
        "check",
        aliases=["doctor"],
        help="check host tools and connected-device compatibility",
    )
    check.add_argument("--serial", required=True)
    check.add_argument("--ndk")
    check.set_defaults(handler=command_check)

    build = sub.add_parser("build", help="build the aarch64 exploit payload from source")
    build.add_argument("--ndk")
    build.add_argument("--profile", help="evidence-backed profile ID")
    build.set_defaults(handler=command_build)

    verify = sub.add_parser("verify", help="verify a live boot-scoped su daemon")
    verify.add_argument("--serial", required=True)
    verify.set_defaults(handler=command_verify)

    report = sub.add_parser(
        "report", help="create an issue-safe report from a private run directory"
    )
    report.add_argument("private_run", type=Path)
    report.add_argument("--output", type=Path)
    report.set_defaults(handler=command_report)

    exploit = sub.add_parser(
        "run",
        aliases=["root"],
        help="run the guarded PoC on an authorized AI Pin",
    )
    exploit.add_argument("--serial", required=True)
    exploit.add_argument("--ndk")
    exploit.add_argument("--no-build", action="store_true")
    exploit.add_argument(
        "--yes",
        "--accept-risk",
        action="store_true",
        help="accept the documented crash, reboot, and hard-hang risk",
    )
    exploit.add_argument("--min-battery", type=int, default=20)
    exploit.add_argument("--output-dir")
    exploit.add_argument(
        "--retain-bugreport",
        action="store_true",
        help="retain the privacy-sensitive raw bugreport in the evidence directory",
    )
    exploit.set_defaults(handler=command_run)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except (GhostLockError, ProfileError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
