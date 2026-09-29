#!/usr/bin/env python3

from __future__ import annotations

import sys
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


sys.path.insert(0, str(Path(__file__).parent))
import ghostlock_prod_runner as RUNNER  # noqa: E402


class ProdRunnerTest(unittest.TestCase):
    class FakeAdb:
        def __init__(self, *, output: str = "", returncode: int = 0):
            self.output = output
            self.returncode = returncode
            self.commands: list[str] = []

        def shell(self, command, *, timeout=30, check=True):
            self.commands.append(command)
            return subprocess.CompletedProcess(
                ["adb", "shell", command], self.returncode, self.output
            )

    def state(self, **overrides):
        values = {
            "serial": "SERIAL",
            "uid": "2000",
            "context": "u:r:shell:s0",
            "selinux": "Enforcing",
            "boot_id": "boot",
            "boot_epoch": "1700000000",
            "uptime_seconds": 1000.0,
            "fingerprint": "fingerprint",
            "kernel": "Linux 4.14.190-perf-debug",
            "slot": "_a",
            "payload_sha256": RUNNER.DEFAULT_PAYLOAD_SHA256,
        }
        values.update(overrides)
        return RUNNER.DeviceState(**values)

    def assert_valid(self, state) -> None:
        RUNNER.assert_production_equivalent(
            state,
            expected_fingerprint="fingerprint",
            expected_payload_sha256=RUNNER.DEFAULT_PAYLOAD_SHA256,
            expected_slot="_a",
            expected_kernel_substring="4.14.190-perf-debug",
        )

    def test_uid_zero_is_rejected(self) -> None:
        with self.assertRaises(RUNNER.RunnerError):
            self.assert_valid(self.state(uid="0", context="u:r:su:s0"))

    def test_default_output_dir_uses_host_temp_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            RUNNER.tempfile, "gettempdir", return_value=temporary
        ):
            path = RUNNER.default_output_dir("20260922-011428")
        self.assertEqual(
            path,
            Path(temporary) / "ghostlock-prod-equivalent-20260922-011428",
        )

    def test_launch_power_gate_requires_level_and_external_power(self) -> None:
        adb = self.FakeAdb(
            output="AC powered: false\nUSB powered: true\nlevel: 87\n"
        )
        self.assertEqual(RUNNER.assert_power(adb, 20), (87, True))
        with self.assertRaisesRegex(RUNNER.RunnerError, "at least 90%"):
            RUNNER.assert_power(adb, 90)

        unplugged = self.FakeAdb(
            output="AC powered: false\nUSB powered: false\nlevel: 100\n"
        )
        with self.assertRaisesRegex(RUNNER.RunnerError, "not connected"):
            RUNNER.assert_power(unplugged, 20)

    def test_attempt_claim_is_boot_specific_and_atomic(self) -> None:
        boot_id = "12345678-1234-1234-1234-123456789abc"
        adb = self.FakeAdb()
        claim = RUNNER.claim_boot_attempt(adb, boot_id)
        self.assertEqual(
            claim,
            "/data/local/tmp/.ghostlock-aipin-attempt."
            + boot_id
            + ".lock",
        )
        self.assertIn("mkdir", adb.commands[0])
        self.assertIn(boot_id, adb.commands[0])

        already_claimed = self.FakeAdb(returncode=1)
        with self.assertRaisesRegex(RUNNER.RunnerError, "already claimed"):
            RUNNER.claim_boot_attempt(already_claimed, boot_id)

    def test_production_boundary_is_accepted(self) -> None:
        self.assert_valid(self.state())

    def test_exploit_environment_has_perf_gate_without_trace_or_host_gate(self) -> None:
        argv = RUNNER.build_exploit_argv(
            0xFFFFFF9F85880000, "/data/local/tmp/preload.so"
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
            mm_object_size=872,
            mm_slab_size=896,
            mm_order=3,
            mm_objects_per_slab=36,
            mm_cpu_partial=13,
        )
        rendered = " ".join(argv)
        self.assertIn("AI_PIN_MM_OBJECT_SIZE=872", rendered)
        self.assertIn("AI_PIN_MM_SLAB_SIZE=896", rendered)

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
            expected_fingerprint="fingerprint",
            expected_payload_sha256=RUNNER.DEFAULT_PAYLOAD_SHA256,
            expected_slot="_a",
            expected_kernel_substring="4.14.190-perf-debug",
            expected_selinux="Permissive",
        )
        with self.assertRaises(RUNNER.RunnerError):
            RUNNER.assert_production_equivalent(
                self.state(uid="0", selinux="Permissive"),
                expected_fingerprint="fingerprint",
                expected_payload_sha256=RUNNER.DEFAULT_PAYLOAD_SHA256,
                expected_slot="_a",
                expected_kernel_substring="4.14.190-perf-debug",
                expected_selinux="Permissive",
            )

    def test_root_markers_require_transition_and_su(self) -> None:
        RUNNER.assert_root_markers(
            "perf reclaim gate result verified=1 pfn=abc memstart=def "
            "free=1 alloc=1 candidates=4 errno=0\n"
            "direct credential result uid=0 euid=0 gid=0 egid=0 "
            "task=abc init_cred=def selinux=1->0 policy_reload=123\n"
            "direct-root-summary root=1 id=1 optional_su=1/0 daemon=42\n"
        )
        with self.assertRaises(RUNNER.RunnerError):
            RUNNER.assert_root_markers(
                "direct-root-summary root=1 id=0 optional_su=0/13\n"
            )


if __name__ == "__main__":
    unittest.main()
