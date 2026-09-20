from __future__ import annotations

import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock


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

    def test_out_of_range_level_is_unknown(self) -> None:
        self.assertEqual(
            GHOSTLOCK.parse_battery("USB powered: true\nlevel: 101\n"),
            (None, True),
        )


class HostDiagnosticsTests(unittest.TestCase):
    @staticmethod
    def create_fake_ndk(path: Path, *, with_compiler: bool = True) -> Path:
        compiler = GHOSTLOCK.ndk_compiler_path(path)
        compiler.parent.mkdir(parents=True)
        if with_compiler:
            compiler.write_text("#!/bin/sh\n", encoding="utf-8")
            compiler.chmod(0o755)
        (path / "source.properties").write_text(
            f"Pkg.Revision = {GHOSTLOCK.PINNED_NDK_VERSION}\n",
            encoding="utf-8",
        )
        return path

    @staticmethod
    def command_check_output(
        *, ndk: Path | None, make: str | None
    ) -> tuple[int, str]:
        serial = "PRIVATE-SERIAL-1234"
        info = TargetTests().info(serial=serial)
        args = mock.Mock(serial=serial, ndk=None)
        output = io.StringIO()
        with mock.patch.object(
            GHOSTLOCK, "select_serial", return_value=serial
        ), mock.patch.object(
            GHOSTLOCK, "inspect_device", return_value=info
        ), mock.patch.object(
            GHOSTLOCK, "find_ndk", return_value=ndk
        ), mock.patch.object(
            GHOSTLOCK.shutil, "which", return_value=make
        ), redirect_stdout(output):
            result = GHOSTLOCK.command_check(args)
        return result, output.getvalue()

    def test_adb_inventory_ignores_daemon_chatter(self) -> None:
        output = (
            "* daemon not running; starting now at tcp:5037\n"
            "* daemon started successfully\n"
            "List of devices attached\n"
            "READY-SERIAL\tdevice\n"
            "PRIVATE-SERIAL\tunauthorized\n"
        )
        completed = subprocess.CompletedProcess(["adb", "devices"], 0, output)
        with mock.patch.object(GHOSTLOCK, "require_command"), mock.patch.object(
            GHOSTLOCK, "run", return_value=completed
        ):
            self.assertEqual(
                GHOSTLOCK.adb_device_inventory(),
                [
                    ("READY-SERIAL", "device"),
                    ("PRIVATE-SERIAL", "unauthorized"),
                ],
            )

    def test_sdk_environment_ndk_is_discovered(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for variable in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
                with self.subTest(variable=variable):
                    sdk = Path(temporary) / variable.lower()
                    ndk = sdk / "ndk" / GHOSTLOCK.PINNED_NDK_VERSION
                    self.create_fake_ndk(ndk)
                    environment = {
                        "ANDROID_SDK_ROOT": "",
                        "ANDROID_HOME": "",
                        "NDK_ROOT": "",
                        "ANDROID_NDK_HOME": "",
                        "ANDROID_NDK_ROOT": "",
                        variable: str(sdk),
                    }
                    with mock.patch.dict(os.environ, environment, clear=False):
                        self.assertEqual(GHOSTLOCK.find_ndk(None), ndk.resolve())

    def test_generic_cc_cannot_override_pinned_android_compiler(self) -> None:
        ndk = Path("/tmp/ghostlock-pinned-ndk")
        environment = os.environ.copy()
        environment.update({"CC": "/usr/bin/false", "NDK_ROOT": str(ndk)})
        result = subprocess.run(
            ["make", "-C", str(GHOSTLOCK.SOURCE), "info"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            env=environment,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        host_tag = (
            "darwin-x86_64" if sys.platform == "darwin" else "linux-x86_64"
        )
        expected = (
            ndk
            / "toolchains/llvm/prebuilt"
            / host_tag
            / "bin"
            / GHOSTLOCK.NDK_TARGET_COMPILER
        )
        self.assertIn(f"TARGET_CC={expected}", result.stdout)
        self.assertNotIn("TARGET_CC=/usr/bin/false", result.stdout)

    def test_command_check_rejects_ndk_without_host_compiler(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ndk = self.create_fake_ndk(root / "ndk", with_compiler=False)
            serial = "PRIVATE-SERIAL-1234"
            info = TargetTests().info(serial=serial)
            args = mock.Mock(serial=serial, ndk=str(ndk))
            environment = {
                "ANDROID_SDK_ROOT": "",
                "ANDROID_HOME": "",
                "NDK_ROOT": "",
                "ANDROID_NDK_HOME": "",
                "ANDROID_NDK_ROOT": "",
            }
            output = io.StringIO()
            with mock.patch.dict(
                os.environ, environment, clear=False
            ), mock.patch.object(
                GHOSTLOCK.Path, "home", return_value=root / "empty-home"
            ), mock.patch.object(
                GHOSTLOCK, "select_serial", return_value=serial
            ), mock.patch.object(
                GHOSTLOCK, "inspect_device", return_value=info
            ), mock.patch.object(
                GHOSTLOCK.shutil, "which", return_value="/usr/bin/make"
            ), redirect_stdout(output):
                result = GHOSTLOCK.command_check(args)
        self.assertEqual(result, 1)
        self.assertIn(
            f"Android NDK: {GHOSTLOCK.PINNED_NDK_VERSION} not found",
            output.getvalue(),
        )
        self.assertIn(
            f"host prerequisites are missing: Android NDK {GHOSTLOCK.PINNED_NDK_VERSION}",
            output.getvalue(),
        )

    def test_command_check_reports_missing_make(self) -> None:
        result, output = self.command_check_output(
            ndk=Path("/valid/ndk"), make=None
        )
        self.assertEqual(result, 1)
        self.assertIn("Make:        not found", output)
        self.assertIn("host prerequisites are missing: make", output)

    def test_command_check_ready_output_redacts_serial(self) -> None:
        serial = "PRIVATE-SERIAL-1234"
        info = TargetTests().info(
            serial=serial,
            kernel=(
                f"Linux {serial} {TargetTests.PROFILE.kernel_release} "
                f"{TargetTests.PROFILE.kernel_build_marker} "
                f"{TargetTests.PROFILE.kernel_machine}"
            ),
        )
        args = mock.Mock(serial=serial, ndk=None)
        captured = io.StringIO()
        with mock.patch.object(
            GHOSTLOCK, "select_serial", return_value=serial
        ), mock.patch.object(
            GHOSTLOCK, "inspect_device", return_value=info
        ), mock.patch.object(
            GHOSTLOCK, "find_ndk", return_value=Path("/valid/ndk")
        ), mock.patch.object(
            GHOSTLOCK.shutil, "which", return_value="/usr/bin/make"
        ), redirect_stdout(captured):
            result = GHOSTLOCK.command_check(args)
        output = captured.getvalue()
        self.assertEqual(result, 0)
        self.assertIn("Device:      <redacted>", output)
        self.assertIn("Kernel:      Linux <nodename>", output)
        self.assertNotIn(serial, output)
        self.assertIn("Status:      ready for a guarded run", output)
        self.assertEqual(output.count("ABI:"), 1)

    def test_adb_state_errors_do_not_disclose_serials(self) -> None:
        inventory = [
            ("READY-SERIAL", "device"),
            ("PRIVATE-SERIAL", "unauthorized"),
        ]
        with mock.patch.object(
            GHOSTLOCK, "adb_device_inventory", return_value=inventory
        ):
            with self.assertRaises(GHOSTLOCK.GhostLockError) as caught:
                GHOSTLOCK.select_serial("MISSING-SERIAL")
        rendered = str(caught.exception)
        self.assertIn("ready=1, unauthorized=1", rendered)
        self.assertNotIn("READY-SERIAL", rendered)
        self.assertNotIn("PRIVATE-SERIAL", rendered)
        self.assertNotIn("MISSING-SERIAL", rendered)

    def test_adb_command_failures_do_not_disclose_serial(self) -> None:
        serial = "PRIVATE-SERIAL-1234"
        failure = GHOSTLOCK.GhostLockError(
            f"command failed (1): adb -s {serial} shell uname -a\n"
            f"adb: device '{serial}' not found"
        )
        with mock.patch.object(GHOSTLOCK, "run", side_effect=failure):
            with self.assertRaises(GHOSTLOCK.GhostLockError) as caught:
                GHOSTLOCK.adb(serial, "shell", "uname -a")
        rendered = str(caught.exception)
        self.assertIn("<serial>", rendered)
        self.assertNotIn(serial, rendered)

    def test_short_serial_is_fully_redacted(self) -> None:
        self.assertEqual(GHOSTLOCK.mask_serial("ABC"), "<redacted>")

    def test_check_style_output_masks_serial_by_default(self) -> None:
        info = TargetTests().info(serial="PRIVATE-SERIAL-1234")
        output = io.StringIO()
        with redirect_stdout(output):
            GHOSTLOCK.print_device(info, TargetTests.PROFILE, ())
        self.assertIn("<redacted>", output.getvalue())
        self.assertNotIn("PRIVATE-SERIAL", output.getvalue())


class TargetTests(unittest.TestCase):
    PROFILES = GHOSTLOCK.load_profiles(GHOSTLOCK.PROFILES_ROOT)
    PROFILE = GHOSTLOCK.profile_by_id(
        PROFILES, "humane-aipin-45.20-nov4"
    )

    def info(self, *, profile=None, **overrides):
        profile = profile or self.PROFILE
        values = {
            "serial": "TESTSERIAL",
            "fingerprint": profile.fingerprint,
            "kernel": (
                f"Linux localhost {profile.kernel_release} "
                f"{profile.kernel_build_marker} {profile.kernel_machine}"
            ),
            "kernel_release": profile.kernel_release,
            "slot": profile.accepted_slots[0],
            "abi": profile.accepted_abis[0],
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

    def test_every_profile_accepts_its_own_exact_identity(self) -> None:
        for expected in self.PROFILES:
            with self.subTest(profile=expected.profile_id):
                profile, mismatches = GHOSTLOCK.evaluate_device(
                    self.info(profile=expected), self.PROFILES
                )
                self.assertEqual(profile, expected)
                self.assertEqual(mismatches, ())

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

    def test_kernel_version_substring_is_rejected(self) -> None:
        info = self.info(
            kernel=(
                f"Linux localhost {self.PROFILE.kernel_release} "
                f"prefix-{self.PROFILE.kernel_build_marker}-suffix "
                f"{self.PROFILE.kernel_machine}"
            )
        )
        profile, mismatches = GHOSTLOCK.evaluate_device(info, self.PROFILES)
        self.assertIsNone(profile)
        self.assertIn("kernel identity", mismatches[0])


class LauncherSafetyTests(unittest.TestCase):
    PROFILE = GHOSTLOCK.load_profiles(GHOSTLOCK.PROFILES_ROOT)[0]

    def test_runner_receives_selected_minimum_battery(self) -> None:
        command = GHOSTLOCK.build_runner_argv(
            serial="TESTSERIAL",
            profile=self.PROFILE,
            payload_sha256="a" * 64,
            output_dir=Path("/private/tmp/ghostlock-test"),
            min_battery=37,
            retain_bugreport=False,
        )

        index = command.index("--min-battery")
        self.assertEqual(command[index + 1], "37")
        self.assertEqual(command.count("--min-battery"), 1)

    def test_minimum_battery_is_bounded(self) -> None:
        self.assertEqual(GHOSTLOCK.min_battery_value("0"), 0)
        self.assertEqual(GHOSTLOCK.min_battery_value("100"), 100)
        for value in ("-1", "101", "unknown"):
            with self.subTest(value=value):
                with self.assertRaises(GHOSTLOCK.argparse.ArgumentTypeError):
                    GHOSTLOCK.min_battery_value(value)


if __name__ == "__main__":
    unittest.main()
