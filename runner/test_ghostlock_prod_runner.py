#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import io
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


sys.path.insert(0, str(Path(__file__).parent))
import ghostlock_prod_runner as RUNNER  # noqa: E402


class RecordingAdb:
    def __init__(self, snapshot: str, *, state: str = "device") -> None:
        self.serial = "SERIAL"
        self.snapshot = snapshot
        self.state = state
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def run(self, *args: str, **_kwargs) -> subprocess.CompletedProcess[str]:
        self.calls.append(("run", args))
        return subprocess.CompletedProcess(args, 0, self.state + "\n", "")

    def shell(self, command: str, **_kwargs) -> subprocess.CompletedProcess[str]:
        self.calls.append(("shell", (command,)))
        return subprocess.CompletedProcess((command,), 0, self.snapshot, "")


class AttemptAdb:
    def __init__(
        self,
        battery: str,
        *,
        battery_returncode: int = 0,
        acquisition_returncode: int = 0,
        acquisition_output: str = "",
    ) -> None:
        self.battery = battery
        self.battery_returncode = battery_returncode
        self.acquisition_returncode = acquisition_returncode
        self.acquisition_output = acquisition_output
        self.calls: list[str] = []

    def shell(self, command: str, **_kwargs) -> subprocess.CompletedProcess[str]:
        self.calls.append(command)
        if command == "dumpsys battery":
            return subprocess.CompletedProcess(
                (command,), self.battery_returncode, self.battery, ""
            )
        return subprocess.CompletedProcess(
            (command,), self.acquisition_returncode, self.acquisition_output, ""
        )


class SharedClaimAdb:
    def __init__(self) -> None:
        self.claimed = False
        self.calls: list[str] = []

    def shell(self, command: str, **_kwargs) -> subprocess.CompletedProcess[str]:
        self.calls.append(command)
        if command == "dumpsys battery":
            return subprocess.CompletedProcess(
                (command,), 0, "USB powered: true\nlevel: 100\n", ""
            )
        if "mkdir" in command:
            if self.claimed:
                return subprocess.CompletedProcess((command,), 73, "", "")
            self.claimed = True
        return subprocess.CompletedProcess((command,), 0, "", "")


class ProdRunnerTest(unittest.TestCase):
    PAYLOAD_SHA256 = "a" * 64
    PROFILES = RUNNER.load_profiles(RUNNER.PROFILES_ROOT)
    PROFILE = RUNNER.profile_by_id(
        PROFILES, "humane-aipin-45.20-nov4"
    )

    def snapshot_values(
        self, *, profile=None, **overrides: str
    ) -> dict[str, str]:
        profile = profile or self.PROFILE
        values = {
            "boot_id_begin": "11111111-2222-3333-4444-555555555555",
            "boot_epoch_begin": "1700000000",
            "uptime_begin": "1000.00",
            "uid": "2000",
            "context": "u:r:shell:s0",
            "selinux": "Enforcing",
            "fingerprint": profile.fingerprint,
            "kernel": (
                f"Linux localhost {profile.kernel_release} "
                f"{profile.kernel_build_marker} {profile.kernel_machine}"
            ),
            "kernel_release": profile.kernel_release,
            "slot": profile.accepted_slots[0],
            "abi": profile.accepted_abis[0],
            "payload_sha256": self.PAYLOAD_SHA256,
            "boot_id_end": "11111111-2222-3333-4444-555555555555",
            "boot_epoch_end": "1700000000",
            "uptime_end": "1000.25",
        }
        values.update(overrides)
        return values

    def snapshot_text(
        self,
        values: dict[str, str] | None = None,
        *,
        omit: str | None = None,
    ) -> str:
        values = values or self.snapshot_values()
        return "".join(
            f"{RUNNER.STATE_SNAPSHOT_PREFIX}\t{tag}\t{values[tag]}\n"
            for tag in RUNNER.STATE_SNAPSHOT_FIELDS
            if tag != omit
        )

    def state(self, *, profile=None, **overrides):
        profile = profile or self.PROFILE
        values = {
            "serial": "SERIAL",
            "uid": "2000",
            "context": "u:r:shell:s0",
            "selinux": "Enforcing",
            "boot_id": "boot",
            "boot_epoch": "1700000000",
            "uptime_seconds": 1000.0,
            "fingerprint": profile.fingerprint,
            "kernel": (
                f"Linux localhost {profile.kernel_release} "
                f"{profile.kernel_build_marker} {profile.kernel_machine}"
            ),
            "kernel_release": profile.kernel_release,
            "slot": profile.accepted_slots[0],
            "abi": profile.accepted_abis[0],
            "payload_sha256": self.PAYLOAD_SHA256,
        }
        values.update(overrides)
        return RUNNER.DeviceState(**values)

    def assert_valid(self, state, *, profile=None) -> None:
        profile = profile or self.PROFILE
        RUNNER.assert_production_equivalent(
            state,
            profile=profile,
            expected_payload_sha256=self.PAYLOAD_SHA256,
        )

    def assert_process_gone(self, pid: int) -> None:
        deadline = time.monotonic() + 1.0
        while True:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            if time.monotonic() >= deadline:
                self.fail(f"helper process {pid} was not reaped")
            time.sleep(0.01)

    def run_hanging_helper(self, *, close_stdout: bool) -> int:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log_path = root / "stream.log"
            close_statement = "os.close(1);os.close(2);" if close_stdout else ""
            helper = (
                "import os, time;"
                f"{close_statement}"
                "time.sleep(60)"
            )
            processes: list[subprocess.Popen[str]] = []
            real_popen = subprocess.Popen

            def start_helper(*args, **kwargs):
                kwargs["preexec_fn"] = lambda: signal.signal(
                    signal.SIGTERM, signal.SIG_IGN
                )
                process = real_popen(*args, **kwargs)
                processes.append(process)
                return process

            def kill_helper_if_needed() -> None:
                if not processes:
                    return
                try:
                    os.kill(processes[0].pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

            self.addCleanup(kill_helper_if_needed)
            with (
                mock.patch.object(
                    RUNNER.subprocess, "Popen", side_effect=start_helper
                ),
                mock.patch.object(
                    RUNNER, "STREAM_TERMINATE_GRACE_SECONDS", 0.05
                ),
                mock.patch.object(RUNNER, "STREAM_REAP_GRACE_SECONDS", 0.5),
                self.assertRaisesRegex(
                    RUNNER.RunnerError, "exploit command exceeded"
                ),
            ):
                RUNNER.stream_process(
                    [sys.executable, "-c", helper],
                    log_path,
                    timeout=0.5,
                )

            self.assertEqual(len(processes), 1)
            self.assert_process_gone(processes[0].pid)
            return processes[0].pid

    def test_capture_state_uses_two_adb_commands_and_preserves_fields(self) -> None:
        adb = RecordingAdb(self.snapshot_text())

        state = RUNNER.capture_state(adb, "/data/local/tmp/preload.so")

        self.assertEqual(len(adb.calls), 2)
        self.assertEqual(adb.calls[0], ("run", ("get-state",)))
        self.assertEqual(adb.calls[1][0], "shell")
        shell_command = adb.calls[1][1][0]
        self.assertLess(
            shell_command.index("boot_id_begin"),
            shell_command.index("boot_id_end"),
        )
        self.assertEqual(state.kernel_release, self.PROFILE.kernel_release)
        self.assertEqual(state.payload_sha256, self.PAYLOAD_SHA256)
        self.assertEqual(state.uptime_seconds, 1000.25)

    def test_stream_process_reaps_no_output_hang_after_deadline(self) -> None:
        self.run_hanging_helper(close_stdout=False)

    def test_stream_process_reaps_stdout_closed_hang_after_deadline(self) -> None:
        self.run_hanging_helper(close_stdout=True)

    def test_stream_cleanup_kills_term_ignoring_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            child_pid_path = Path(directory) / "child.pid"
            child = (
                "import os, pathlib, signal, sys, time;"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
                "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()));"
                "time.sleep(60)"
            )
            leader = (
                "import subprocess, sys, time;"
                "subprocess.Popen([sys.executable, '-c', sys.argv[1], "
                "sys.argv[2]], stdout=subprocess.DEVNULL, "
                "stderr=subprocess.DEVNULL);"
                "time.sleep(60)"
            )
            process = subprocess.Popen(
                [sys.executable, "-c", leader, child, str(child_pid_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
                start_new_session=True,
            )

            def kill_group_if_needed() -> None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

            self.addCleanup(kill_group_if_needed)
            deadline = time.monotonic() + 2.0
            while not child_pid_path.is_file() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(child_pid_path.is_file(), "descendant was not ready")
            child_pid = int(child_pid_path.read_text(encoding="utf-8"))

            with (
                mock.patch.object(
                    RUNNER, "STREAM_TERMINATE_GRACE_SECONDS", 0.05
                ),
                mock.patch.object(RUNNER, "STREAM_REAP_GRACE_SECONDS", 0.5),
            ):
                cleanup_error = RUNNER._stop_and_reap_stream_process(
                    process, None
                )

            self.assertIsNone(cleanup_error)
            self.assert_process_gone(process.pid)
            self.assert_process_gone(child_pid)

    def test_stream_process_rejects_non_utf8_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "stream.log"
            with self.assertRaisesRegex(
                RUNNER.RunnerError, "could not read exploit output"
            ):
                RUNNER.stream_process(
                    [sys.executable, "-c", "import os; os.write(1, b'\\xff')"],
                    log_path,
                    timeout=1.0,
                )

    def test_stream_cancellation_survives_cleanup_and_drain_failures(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "stream.log"
            real_cleanup = RUNNER._stop_and_reap_stream_process

            def cleanup_then_report(process, reader_thread):
                error = real_cleanup(process, reader_thread)
                self.assertIsNone(error)
                return "synthetic cleanup failure"

            with (
                mock.patch.object(
                    RUNNER.queue.Queue,
                    "get",
                    side_effect=KeyboardInterrupt(),
                ),
                mock.patch.object(
                    RUNNER.queue.Queue,
                    "get_nowait",
                    side_effect=OSError("synthetic drain failure"),
                ),
                mock.patch.object(
                    RUNNER,
                    "_stop_and_reap_stream_process",
                    side_effect=cleanup_then_report,
                ),
                self.assertRaises(KeyboardInterrupt) as caught,
            ):
                RUNNER.stream_process(
                    [sys.executable, "-c", "import time; time.sleep(60)"],
                    log_path,
                    timeout=1.0,
                )

            notes = getattr(caught.exception, "__notes__", ())
            if notes:
                self.assertIn("synthetic cleanup failure", notes[0])
                self.assertIn("synthetic drain failure", notes[0])

    def test_capture_state_rejects_duplicate_tag(self) -> None:
        snapshot = self.snapshot_text()
        duplicate = (
            f"{RUNNER.STATE_SNAPSHOT_PREFIX}\tuid\t2000\n"
        )
        adb = RecordingAdb(snapshot + duplicate)

        with self.assertRaisesRegex(RUNNER.RunnerError, "duplicate.*uid"):
            RUNNER.capture_state(adb, "/data/local/tmp/preload.so")

    def test_capture_state_rejects_missing_tag(self) -> None:
        adb = RecordingAdb(self.snapshot_text(omit="kernel_release"))

        with self.assertRaisesRegex(RUNNER.RunnerError, "missing.*kernel_release"):
            RUNNER.capture_state(adb, "/data/local/tmp/preload.so")

    def test_capture_state_rejects_malformed_record(self) -> None:
        adb = RecordingAdb("unexpected output\n" + self.snapshot_text())

        with self.assertRaisesRegex(RUNNER.RunnerError, "malformed.*line 1"):
            RUNNER.capture_state(adb, "/data/local/tmp/preload.so")

    def test_capture_state_rejects_unknown_tag(self) -> None:
        snapshot = self.snapshot_text() + (
            f"{RUNNER.STATE_SNAPSHOT_PREFIX}\tunknown\tvalue\n"
        )
        adb = RecordingAdb(snapshot)

        with self.assertRaisesRegex(RUNNER.RunnerError, "unexpected.*unknown"):
            RUNNER.capture_state(adb, "/data/local/tmp/preload.so")

    def test_capture_state_rejects_mixed_boot_identity(self) -> None:
        changes = (
            ("boot_id_end", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "boot ID"),
            ("boot_epoch_end", "1700000001", "boot epoch"),
            ("uptime_end", "1.00", "uptime moved backwards"),
        )
        for tag, value, error in changes:
            with self.subTest(tag=tag):
                adb = RecordingAdb(
                    self.snapshot_text(self.snapshot_values(**{tag: value}))
                )
                with self.assertRaisesRegex(RUNNER.RunnerError, error):
                    RUNNER.capture_state(adb, "/data/local/tmp/preload.so")

    def test_capture_state_allows_expected_post_exploit_boot_id_scratch(self) -> None:
        scratch = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        adb = RecordingAdb(
            self.snapshot_text(self.snapshot_values(boot_id_end=scratch))
        )

        state = RUNNER.capture_state(
            adb,
            "/data/local/tmp/preload.so",
            allow_boot_id_scratch=True,
        )

        self.assertEqual(state.boot_id, scratch)
        self.assertEqual(state.boot_epoch, "1700000000")

    def test_capture_state_rejects_malformed_hash_and_uptime(self) -> None:
        changes = (
            ("payload_sha256", "not-a-hash", "cannot hash remote payload"),
            ("uptime_end", "nan", "invalid kernel uptime"),
        )
        for tag, value, error in changes:
            with self.subTest(tag=tag):
                adb = RecordingAdb(
                    self.snapshot_text(self.snapshot_values(**{tag: value}))
                )
                with self.assertRaisesRegex(RUNNER.RunnerError, error):
                    RUNNER.capture_state(adb, "/data/local/tmp/preload.so")

    def test_attempt_claim_rechecks_power_immediately_before_atomic_write(self) -> None:
        adb = AttemptAdb(
            "AC powered: false\nUSB powered: true\n"
            "Wireless powered: false\nlevel: 67\n"
        )

        RUNNER.acquire_same_boot_attempt(
            adb,
            self.state(),
            RUNNER.DEFAULT_ATTEMPT_MARKER,
            min_battery=20,
        )

        self.assertEqual(adb.calls[0], "dumpsys battery")
        claim = adb.calls[1]
        self.assertLess(claim.index("observed_boot_id"), claim.index("mkdir"))
        self.assertLess(claim.index("observed_boot_epoch"), claim.index("mkdir"))
        self.assertLess(claim.index("mkdir"), claim.rindex("printf"))
        self.assertEqual(len(adb.calls), 2)

    def test_reboot_before_atomic_claim_stops_without_using_stale_kaslr(self) -> None:
        adb = AttemptAdb(
            "USB powered: true\nlevel: 100\n",
            acquisition_returncode=RUNNER.ATTEMPT_BOOT_CHANGED_EXIT,
            acquisition_output=RUNNER.ATTEMPT_BOOT_CHANGED_SENTINEL + "\n",
        )

        with self.assertRaisesRegex(
            RUNNER.RunnerError, "rebooted immediately before the attempt"
        ):
            RUNNER.acquire_same_boot_attempt(
                adb,
                self.state(),
                RUNNER.DEFAULT_ATTEMPT_MARKER,
                min_battery=20,
            )

        self.assertEqual(adb.calls[0], "dumpsys battery")
        claim = adb.calls[1]
        self.assertLess(claim.index("exit 74"), claim.index("mkdir"))
        self.assertIn(self.state().boot_id, claim)
        self.assertIn(self.state().boot_epoch, claim)

    def test_attempt_claim_is_not_consumed_when_power_gate_fails(self) -> None:
        cases = (
            ("status: 2\n", 0, "unavailable"),
            ("USB powered: true\nlevel: 101\n", 0, "unavailable"),
            ("USB powered: true\nlevel: 19\n", 0, "fell to 19%"),
            ("USB powered: false\nlevel: 80\n", 0, "disconnected"),
            ("USB powered: true\nlevel: 80\n", 1, "unavailable"),
        )
        for battery, returncode, error in cases:
            with self.subTest(error=error, returncode=returncode):
                adb = AttemptAdb(battery, battery_returncode=returncode)
                with self.assertRaisesRegex(RUNNER.RunnerError, error):
                    RUNNER.acquire_same_boot_attempt(
                        adb,
                        self.state(),
                        RUNNER.DEFAULT_ATTEMPT_MARKER,
                        min_battery=20,
                    )
                self.assertEqual(adb.calls, ["dumpsys battery"])

    def test_zero_minimum_skips_power_gate_without_skipping_marker(self) -> None:
        adb = AttemptAdb("unavailable")

        RUNNER.acquire_same_boot_attempt(
            adb,
            self.state(),
            RUNNER.DEFAULT_ATTEMPT_MARKER,
            min_battery=0,
        )

        self.assertEqual(len(adb.calls), 1)
        self.assertLess(adb.calls[0].index("mkdir"), adb.calls[0].rindex("printf"))

    def test_failed_atomic_acquisition_stops_the_attempt(self) -> None:
        adb = AttemptAdb(
            "USB powered: true\nlevel: 100\n",
            acquisition_returncode=73,
        )

        with self.assertRaisesRegex(RUNNER.RunnerError, "atomically acquire"):
            RUNNER.acquire_same_boot_attempt(
                adb,
                self.state(),
                RUNNER.DEFAULT_ATTEMPT_MARKER,
                min_battery=20,
            )

        self.assertEqual(adb.calls[0], "dumpsys battery")
        self.assertEqual(sum("mkdir" in command for command in adb.calls), 1)

    def test_atomic_claim_allows_only_one_same_boot_runner(self) -> None:
        adb = SharedClaimAdb()

        RUNNER.acquire_same_boot_attempt(
            adb,
            self.state(),
            RUNNER.DEFAULT_ATTEMPT_MARKER,
            min_battery=20,
        )
        with self.assertRaisesRegex(RUNNER.RunnerError, "another runner"):
            RUNNER.acquire_same_boot_attempt(
                adb,
                self.state(),
                RUNNER.DEFAULT_ATTEMPT_MARKER,
                min_battery=20,
            )

        self.assertEqual(sum("mkdir" in command for command in adb.calls), 2)

    def test_attempt_claim_is_stable_per_boot_and_changes_after_reboot(self) -> None:
        initial = RUNNER.attempt_lock_path(
            self.state(), RUNNER.DEFAULT_ATTEMPT_MARKER
        )
        same_boot = RUNNER.attempt_lock_path(
            self.state(uptime_seconds=2000.0), RUNNER.DEFAULT_ATTEMPT_MARKER
        )
        next_boot = RUNNER.attempt_lock_path(
            self.state(boot_epoch="1700000001"), RUNNER.DEFAULT_ATTEMPT_MARKER
        )

        self.assertEqual(initial, same_boot)
        self.assertNotEqual(initial, next_boot)
        self.assertTrue(initial.endswith(".lock"))

    def test_preflight_rejects_an_existing_atomic_claim(self) -> None:
        adb = RecordingAdb(RUNNER.ATTEMPT_CLAIMED_SENTINEL + "\n")

        with self.assertRaisesRegex(RUNNER.RunnerError, "already had"):
            RUNNER.ensure_no_same_boot_attempt(
                adb, self.state(), RUNNER.DEFAULT_ATTEMPT_MARKER
            )

        command = adb.calls[0][1][0]
        self.assertIn("[ -d", command)
        self.assertIn(
            RUNNER.attempt_lock_path(self.state(), RUNNER.DEFAULT_ATTEMPT_MARKER),
            command,
        )

    def test_phase_timer_records_only_fixed_monotonic_durations(self) -> None:
        observed = iter((100.0, 100.0, 105.4321, 106.0, 110.0, 112.0, 113.0))
        timer = RUNNER.PhaseTimer(clock=lambda: next(observed))

        timer.start("preflight")
        timer.finish()
        timer.start("exploit")
        active = timer.snapshot()
        timer.finish()
        complete = timer.snapshot()

        self.assertEqual(active["preflight"], 5.432)
        self.assertEqual(active["exploit"], 4.0)
        self.assertEqual(active["total"], 10.0)
        self.assertEqual(complete["exploit"], 6.0)
        self.assertEqual(complete["total"], 13.0)
        self.assertEqual(
            set(complete), {"preflight", "exploit", "total"}
        )

    def test_uid_zero_is_rejected(self) -> None:
        with self.assertRaises(RUNNER.RunnerError):
            self.assert_valid(self.state(uid="0", context="u:r:su:s0"))

    def test_production_boundary_is_accepted(self) -> None:
        self.assert_valid(self.state())

    def test_every_profile_accepts_its_own_production_boundary(self) -> None:
        for profile in self.PROFILES:
            with self.subTest(profile=profile.profile_id):
                self.assert_valid(
                    self.state(profile=profile), profile=profile
                )

    def test_nearby_kernel_release_is_rejected(self) -> None:
        with self.assertRaisesRegex(RUNNER.RunnerError, "kernel release"):
            self.assert_valid(
                self.state(kernel_release=f"{self.PROFILE.kernel_release}-different")
            )

    def test_exploit_environment_has_perf_gate_without_trace_or_host_gate(self) -> None:
        argv = RUNNER.build_exploit_argv(
            0xFFFFFF9F85880000,
            "/data/local/tmp/preload.so",
            geometry=self.PROFILE.allocator_geometry,
        )
        rendered = " ".join(argv)
        self.assertIn("AI_PIN_KASLR_BASE=0xffffff9f85880000", rendered)
        self.assertIn("AI_PIN_SLIDE_LEAK=2", rendered)
        self.assertIn("AI_PIN_PERF_RECLAIM_GATE=1", rendered)
        self.assertNotIn("TRACE", rendered)
        self.assertNotIn("AI_PIN_RECLAIM_GATE_", rendered)

    def test_exploit_environment_accepts_profile_geometry(self) -> None:
        argv = RUNNER.build_exploit_argv(
            0xFFFFFF9F85880000,
            "/data/local/tmp/preload.so",
            geometry=RUNNER.AllocatorGeometry(
                object_size=872,
                slab_size=896,
                order=3,
                objects_per_slab=36,
                cpu_partial=13,
            ),
        )
        rendered = " ".join(argv)
        self.assertIn("AI_PIN_MM_OBJECT_SIZE=872", rendered)
        self.assertIn("AI_PIN_MM_SLAB_SIZE=896", rendered)

    def test_exploit_launch_rechecks_boot_in_the_exec_shell(self) -> None:
        state = self.state()
        argv = RUNNER.build_exploit_argv(
            0xFFFFFF9F85880000,
            "/data/local/tmp/preload.so",
            geometry=self.PROFILE.allocator_geometry,
        )

        command = RUNNER.build_guarded_exploit_command(state, argv)

        self.assertIn(state.boot_id, command)
        self.assertIn(state.boot_epoch, command)
        self.assertIn(RUNNER.ATTEMPT_BOOT_CHANGED_SENTINEL, command)
        self.assertLess(command.index("observed_boot_id"), command.index("exec "))
        self.assertLess(command.index("exit 74"), command.index("exec "))
        self.assertEqual(command.count("/system/bin/env"), 1)

    def test_same_boot_rejects_boot_change(self) -> None:
        with self.assertRaises(RUNNER.RunnerError):
            RUNNER.assert_same_boot(self.state(), self.state(boot_id="new-boot"))

    def test_post_exploit_allows_boot_id_scratch_on_same_kernel_boot(self) -> None:
        RUNNER.assert_same_boot(
            self.state(),
            self.state(boot_id="scratch-value", uptime_seconds=1100.0),
            allow_boot_id_scratch=True,
        )

    def test_post_exploit_rejects_real_reboot(self) -> None:
        with self.assertRaises(RUNNER.RunnerError):
            RUNNER.assert_same_boot(
                self.state(),
                self.state(
                    boot_id="new-boot",
                    boot_epoch="1700001000",
                    uptime_seconds=20.0,
                ),
                allow_boot_id_scratch=True,
            )

    def test_post_exploit_requires_shell_adbd_and_permissive_transition(self) -> None:
        RUNNER.assert_production_equivalent(
            self.state(selinux="Permissive", boot_id="scratch-value"),
            profile=self.PROFILE,
            expected_payload_sha256=self.PAYLOAD_SHA256,
            expected_selinux="Permissive",
        )
        with self.assertRaises(RUNNER.RunnerError):
            RUNNER.assert_production_equivalent(
                self.state(uid="0", selinux="Permissive"),
                profile=self.PROFILE,
                expected_payload_sha256=self.PAYLOAD_SHA256,
                expected_selinux="Permissive",
            )

    def test_root_markers_require_transition_and_su(self) -> None:
        RUNNER.assert_root_markers(
            f"target kernel accepted profile={self.PROFILE.profile_id} "
            f"manifest_sha256={self.PROFILE.manifest_sha256} "
            f"image_sha256={self.PROFILE.kernel_image_sha256} "
            f"symbols_sha256={self.PROFILE.symbols_sha256} "
            f"slot={self.PROFILE.accepted_slots[0]} "
            f"abi={self.PROFILE.accepted_abis[0]}\n"
            "perf reclaim gate result verified=1 pfn=abc memstart=def "
            "free=1 alloc=1 candidates=4 errno=0\n"
            "direct credential result uid=0 euid=0 gid=0 egid=0 "
            "task=abc init_cred=def selinux=1->0 policy_reload=123\n"
            "direct-root-summary root=1 id=1 su=1/0 daemon=42\n",
            self.PROFILE,
        )
        with self.assertRaises(RUNNER.RunnerError):
            RUNNER.assert_root_markers(
                "direct-root-summary root=1 id=0 su=0/13\n",
                self.PROFILE,
            )

    def test_payload_must_embed_all_profile_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            payload = Path(directory) / "preload.so"
            payload.write_bytes(
                b"payload\0"
                + self.PROFILE.manifest_sha256.encode()
                + b"\0"
                + self.PROFILE.kernel_image_sha256.encode()
                + b"\0"
                + self.PROFILE.symbols_sha256.encode()
            )
            digest = RUNNER.sha256_file(payload)
            RUNNER.assert_payload_profile_binding(payload, self.PROFILE, digest)
            payload.write_bytes(b"stale payload")
            stale_digest = RUNNER.sha256_file(payload)
            with self.assertRaisesRegex(RUNNER.RunnerError, "not bound"):
                RUNNER.assert_payload_profile_binding(
                    payload, self.PROFILE, stale_digest
                )

    def test_direct_runner_rejects_manifest_hash_drift(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                RUNNER.main(
                    [
                        "--serial",
                        "SERIAL",
                        "--profile-id",
                        self.PROFILE.profile_id,
                        "--profile-sha256",
                        "0" * 64,
                        "--payload-sha256",
                        self.PAYLOAD_SHA256,
                    ]
                )
        self.assertEqual(raised.exception.code, 2)

    def test_direct_runner_rejects_out_of_range_minimum_battery(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                RUNNER.main(
                    [
                        "--serial",
                        "SERIAL",
                        "--profile-id",
                        self.PROFILE.profile_id,
                        "--profile-sha256",
                        self.PROFILE.manifest_sha256,
                        "--payload-sha256",
                        self.PAYLOAD_SHA256,
                        "--min-battery",
                        "101",
                    ]
                )
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
