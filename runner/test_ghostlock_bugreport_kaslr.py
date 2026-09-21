#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("ghostlock_bugreport_kaslr.py")
SPEC = importlib.util.spec_from_file_location("ghostlock_bugreport_kaslr", MODULE_PATH)
assert SPEC and SPEC.loader
KASLR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = KASLR
SPEC.loader.exec_module(KASLR)


BOOT_ID = "a7f9be5d-5f1f-4555-8c0d-48f76f6ff12e"
SERIAL = "1H4MPA3B304157"
FINGERPRINT = (
    "qti/atoll/atoll:12/SKQ1.230401.001/101.000470.45.10:userdebug/test-keys"
)


class BugreportKaslrTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.symbols = self.root / "kallsyms.txt"
        self.symbols.write_text(
            "ffffff8008080000 T _text\n"
            "ffffff80082700b0 T free_pgtables\n"
            "ffffff800827cc20 T exit_mmap\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def make_report(
        self,
        *,
        lr_header: str = "ffffff9f85a7cc70",
        boot=BOOT_ID,
        dedicated_kernel_buffer: bool = True,
    ) -> Path:
        buffer_marker = (
            "--------- beginning of kernel"
            if dedicated_kernel_buffer
            else "--------- beginning of main"
        )
        dump_prefix = "01-01 W :" if dedicated_kernel_buffer else "<4>[ 1.0]"
        report = f"""========================================================
Build fingerprint: '{FINGERPRINT}'
Command line: androidboot.serialno={SERIAL} androidboot.slot_suffix=_a
stale archived text PC      : 0xffffff80082701c0:
linuxBootId={boot}
------ SYSTEM LOG (logcat -v threadtime -d *:v) ------
{buffer_marker}
01-01 W WARNING: CPU: 1 PID: 474 at mm.h free_pgtables+0x150/0x158
01-01 W pc      : free_pgtables+0x150/0x158
01-01 W lr      : exit_mmap+0x90/0x1c0
01-01 W PC      : 0xffffff9f85a701c0:
01-01 W LR      : 0x{lr_header}:
01-01 W SP      : 0xffffff801490baf0:
{dump_prefix} baf0  85a70200 ffffff9f 20000005 00000000 00000000 00000000 00000000 00000000
{dump_prefix} bb30  00000000 00000000 85a7ccb0 ffffff9f 00000000 00000000 00000000 00000000
01-01 W Call trace:
01-01 W ---[ end trace abc ]---
--------- beginning of main
"""
        path = self.root / "report.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("bugreport-atoll.txt", report)
            archive.writestr(
                "FS/data/misc/logd/logcat.01",
                "WARNING stale PC      : 0xffffff80082701c0:",
            )
        return path

    def parse(self, path: Path):
        return KASLR.parse_bugreport(
            path,
            self.symbols,
            expected_boot_id=BOOT_ID,
            expected_serial=SERIAL,
            expected_fingerprint=FINGERPRINT,
        )

    def test_two_independent_anchors_agree(self) -> None:
        result = self.parse(self.make_report())
        self.assertEqual(result.slide, 0x1F7D800000)
        self.assertEqual(result.runtime_text_base, 0xFFFFFF9F85880000)
        self.assertEqual({a.symbol for a in result.anchors}, {"free_pgtables", "exit_mmap"})

    def test_mismatched_anchor_fails_closed(self) -> None:
        with self.assertRaises(KASLR.KaslrParseError):
            self.parse(self.make_report(lr_header="ffffff9f85c7cc70"))

    def test_retail_main_buffer_is_accepted(self) -> None:
        result = self.parse(self.make_report(dedicated_kernel_buffer=False))
        self.assertEqual(result.slide, 0x1F7D800000)
        self.assertEqual(
            {anchor.symbol for anchor in result.anchors},
            {"free_pgtables", "exit_mmap"},
        )

    def test_wrong_boot_id_fails_closed(self) -> None:
        with self.assertRaises(KASLR.KaslrParseError):
            self.parse(self.make_report(boot="00000000-0000-0000-0000-000000000000"))


if __name__ == "__main__":
    unittest.main()
