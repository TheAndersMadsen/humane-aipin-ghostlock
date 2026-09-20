from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("ghostlock.py")
SPEC = importlib.util.spec_from_file_location("ghostlock_cli", MODULE_PATH)
assert SPEC and SPEC.loader
GHOSTLOCK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GHOSTLOCK
SPEC.loader.exec_module(GHOSTLOCK)


class BatteryParsingTests(unittest.TestCase):
    def test_parses_level_and_any_power_source(self) -> None:
        level, powered = GHOSTLOCK.parse_battery(
            "AC powered: false\nUSB powered: true\nWireless powered: false\nlevel: 87\n"
        )
        self.assertEqual(level, 87)
        self.assertTrue(powered)

    def test_missing_values_remain_unknown(self) -> None:
        self.assertEqual(GHOSTLOCK.parse_battery("status: 2\n"), (None, None))


class TargetTests(unittest.TestCase):
    PROFILES = GHOSTLOCK.load_profiles(GHOSTLOCK.PROFILES_ROOT)
    PROFILE = PROFILES[0]

    def info(self, **overrides):
        values = {
            "serial": "TESTSERIAL",
            "fingerprint": self.PROFILE.fingerprint,
            "kernel": (
                f"Linux localhost {self.PROFILE.kernel_release} "
                f"{self.PROFILE.kernel_build_marker} aarch64"
            ),
            "kernel_release": self.PROFILE.kernel_release,
            "slot": self.PROFILE.accepted_slots[0],
            "abi": self.PROFILE.accepted_abis[0],
            "uid": "2000",
            "context": "u:r:shell:s0",
            "selinux": "Enforcing",
            "battery_level": 100,
            "powered": True,
        }
        values.update(overrides)
        return GHOSTLOCK.DeviceInfo(**values)

    def test_exact_profile_is_supported_and_clean(self) -> None:
        info = self.info()
        profile, mismatches = GHOSTLOCK.evaluate_device(info, self.PROFILES)
        self.assertEqual(profile, self.PROFILE)
        self.assertEqual(mismatches, ())
        self.assertTrue(info.clean_shell)

    def test_nearby_firmware_is_rejected(self) -> None:
        info = self.info(
            fingerprint=self.PROFILE.fingerprint.replace("45.20", "45.21")
        )
        profile, mismatches = GHOSTLOCK.evaluate_device(info, self.PROFILES)
        self.assertIsNone(profile)
        self.assertIn("firmware fingerprint", mismatches[0])

    def test_unproven_slot_a_is_rejected(self) -> None:
        info = self.info(slot="_a")
        profile, mismatches = GHOSTLOCK.evaluate_device(info, self.PROFILES)
        self.assertIsNone(profile)
        self.assertEqual(
            mismatches,
            ("active slot: expected '_b', observed '_a'",),
        )

    def test_nearby_kernel_release_is_rejected(self) -> None:
        info = self.info(kernel_release=f"{self.PROFILE.kernel_release}-different")
        profile, mismatches = GHOSTLOCK.evaluate_device(info, self.PROFILES)
        self.assertIsNone(profile)
        self.assertEqual(
            mismatches,
            (
                "kernel release: expected '4.14.190-perf', "
                "observed '4.14.190-perf-different'",
            ),
        )


if __name__ == "__main__":
    unittest.main()
