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
    def test_exact_profile_is_supported_and_clean(self) -> None:
        info = GHOSTLOCK.DeviceInfo(
            serial="TESTSERIAL",
            fingerprint=GHOSTLOCK.SUPPORTED_FINGERPRINT,
            kernel=f"Linux localhost {GHOSTLOCK.SUPPORTED_KERNEL_MARKER} aarch64",
            slot="_b",
            abi=GHOSTLOCK.SUPPORTED_ABI,
            uid="2000",
            context="u:r:shell:s0",
            selinux="Enforcing",
            battery_level=100,
            powered=True,
        )
        self.assertTrue(info.supported)
        self.assertTrue(info.clean_shell)

    def test_nearby_firmware_is_rejected(self) -> None:
        info = GHOSTLOCK.DeviceInfo(
            serial="TESTSERIAL",
            fingerprint=GHOSTLOCK.SUPPORTED_FINGERPRINT.replace("45.20", "45.21"),
            kernel=f"Linux localhost {GHOSTLOCK.SUPPORTED_KERNEL_MARKER} aarch64",
            slot="_b",
            abi=GHOSTLOCK.SUPPORTED_ABI,
            uid="2000",
            context="u:r:shell:s0",
            selinux="Enforcing",
            battery_level=100,
            powered=True,
        )
        self.assertFalse(info.supported)

    def test_unproven_slot_a_is_rejected(self) -> None:
        info = GHOSTLOCK.DeviceInfo(
            serial="TESTSERIAL",
            fingerprint=GHOSTLOCK.SUPPORTED_FINGERPRINT,
            kernel=f"Linux localhost {GHOSTLOCK.SUPPORTED_KERNEL_MARKER} aarch64",
            slot="_a",
            abi=GHOSTLOCK.SUPPORTED_ABI,
            uid="2000",
            context="u:r:shell:s0",
            selinux="Enforcing",
            battery_level=100,
            powered=True,
        )
        self.assertFalse(info.supported)


if __name__ == "__main__":
    unittest.main()
