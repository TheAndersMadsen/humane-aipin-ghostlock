from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("redact_report.py")
SPEC = importlib.util.spec_from_file_location("redact_report", MODULE_PATH)
assert SPEC and SPEC.loader
REDACTOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = REDACTOR
SPEC.loader.exec_module(REDACTOR)


class RedactionTests(unittest.TestCase):
    def test_private_identifiers_and_addresses_are_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private_path = "/" + "home/private/evidence"
            manifest = {
                "result": "root-via-production-equivalent-chain",
                "mode": "execute",
                "serial": "PRIVATE-SERIAL",
                "output_dir": private_path,
                "initial_state": {
                    "serial": "PRIVATE-SERIAL",
                    "boot_id": "PRIVATE-BOOT-ID",
                    "fingerprint": "public-fingerprint",
                    "slot": "_b",
                    "uid": "2000",
                    "context": "u:r:shell:s0",
                    "selinux": "Enforcing",
                    "payload_sha256": "a" * 64,
                },
                "kaslr": {
                    "runtime_text_base": "0xffffffaa00000000",
                    "anchors": [
                        {
                            "symbol": "exit_mmap",
                            "runtime_address": "0xffffffaa00123456",
                        }
                    ],
                },
                "acceptance_returncode": 0,
                "acceptance_output": "uid=0(root) gid=0(root)",
            }
            (root / "manifest.json").write_text(json.dumps(manifest))
            (root / "run.log").write_text(
                "kernel address ffffffaa00123456\n"
                "perf reclaim gate result verified=1 pfn=abc free=1 alloc=1\n"
                "direct credential result uid=0 euid=0 gid=0 egid=0 "
                "selinux=1->0\n"
                "direct-root-summary root=1 id=1 su=1/0\n"
            )

            rendered = json.dumps(REDACTOR.redact(root))
            self.assertNotIn("PRIVATE-SERIAL", rendered)
            self.assertNotIn("PRIVATE-BOOT-ID", rendered)
            self.assertNotIn(private_path, rendered)
            self.assertNotIn("ffffffaa", rendered)
            self.assertTrue(json.loads(rendered)["acceptance_ok"])


if __name__ == "__main__":
    unittest.main()
