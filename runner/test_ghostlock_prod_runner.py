#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent))
import ghostlock_prod_runner as RUNNER  # noqa: E402


class ProdRunnerTest(unittest.TestCase):
    PAYLOAD_SHA256 = "a" * 64
    PROFILE = RUNNER.load_profiles(RUNNER.PROFILES_ROOT)[0]

    def state(self, **overrides):
        values = {
            "serial": "SERIAL",
            "uid": "2000",
            "context": "u:r:shell:s0",
            "selinux": "Enforcing",
            "boot_id": "boot",
            "boot_epoch": "1700000000",
            "uptime_seconds": 1000.0,
            "fingerprint": self.PROFILE.fingerprint,
            "kernel": (
                f"Linux localhost {self.PROFILE.kernel_release} "
                f"{self.PROFILE.kernel_build_marker} aarch64"
            ),
            "kernel_release": self.PROFILE.kernel_release,
            "slot": self.PROFILE.accepted_slots[0],
            "abi": self.PROFILE.accepted_abis[0],
            "payload_sha256": self.PAYLOAD_SHA256,
        }
        values.update(overrides)
        return RUNNER.DeviceState(**values)

    def assert_valid(self, state) -> None:
        RUNNER.assert_production_equivalent(
            state,
            profile=self.PROFILE,
            expected_payload_sha256=self.PAYLOAD_SHA256,
        )

    def test_uid_zero_is_rejected(self) -> None:
        with self.assertRaises(RUNNER.RunnerError):
            self.assert_valid(self.state(uid="0", context="u:r:su:s0"))

    def test_production_boundary_is_accepted(self) -> None:
        self.assert_valid(self.state())

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
            f"symbols_sha256={self.PROFILE.symbols_sha256} slot=_b abi=arm64-v8a\n"
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


if __name__ == "__main__":
    unittest.main()
