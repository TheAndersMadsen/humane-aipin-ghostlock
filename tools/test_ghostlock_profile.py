from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ghostlock_profile import ProfileError, load_profile, load_profiles  # noqa: E402
from scripts.generate_profile_header import validate_target_layout  # noqa: E402


class ProfileLoadingTests(unittest.TestCase):
    BUNDLED = ROOT / "profiles/humane-45.20/profile.json"

    def test_bundled_profile_binds_symbols(self) -> None:
        profile = load_profile(self.BUNDLED)
        self.assertEqual(profile.profile_id, "humane-aipin-45.20-nov4")
        self.assertEqual(profile.symbols_path.name, "symbols.txt")
        self.assertEqual(len(profile.manifest_sha256), 64)

    def test_missing_manifest_fails_closed(self) -> None:
        with self.assertRaisesRegex(ProfileError, "cannot read profile manifest"):
            load_profile(Path("/definitely/missing/ghostlock-profile.json"))

    def test_missing_or_unknown_fields_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.json"
            path.write_text(
                json.dumps({"schema_version": 1, "unexpected": True}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ProfileError, "fields are invalid"):
                load_profile(path)

    def test_symbols_substitution_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            profile_dir = Path(directory)
            shutil.copy2(self.BUNDLED, profile_dir / "profile.json")
            (profile_dir / "symbols.txt").write_text(
                "ffffffffffffffff T _text\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ProfileError, "symbols hash mismatch"):
                load_profile(profile_dir / "profile.json")

    def write_profile(
        self,
        root: Path,
        name: str,
        *,
        project: str,
        slot: str = "_b",
    ) -> None:
        target = root / name
        target.mkdir()
        data = json.loads(self.BUNDLED.read_text(encoding="utf-8"))
        data["profile_id"] = f"{name}-profile"
        data["project"] = project
        data["accepted_slots"] = [slot]
        (target / "profile.json").write_text(json.dumps(data), encoding="utf-8")
        shutil.copy2(self.BUNDLED.with_name("symbols.txt"), target / "symbols.txt")

    def test_reusing_target_project_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_profile(root, "first", project="same-target")
            self.write_profile(root, "second", project="same-target")
            with self.assertRaisesRegex(
                ProfileError, "multiple profiles target project"
            ):
                load_profiles(root)

    def test_overlapping_live_identities_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_profile(root, "first", project="first-target")
            self.write_profile(root, "second", project="second-target")
            with self.assertRaisesRegex(ProfileError, "ambiguous live identity"):
                load_profiles(root)

    def test_disjoint_slots_can_have_separate_projects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_profile(root, "first", project="first-target", slot="_a")
            self.write_profile(root, "second", project="second-target", slot="_b")
            self.assertEqual(len(load_profiles(root)), 2)

    def test_target_layout_must_match_profile_image(self) -> None:
        profile = load_profile(self.BUNDLED)
        target_header = (
            ROOT / "source/src/targets/humane-aipin-45.20/target.h"
        )
        validate_target_layout(profile, target_header)
        with tempfile.TemporaryDirectory() as directory:
            wrong = Path(directory) / "target.h"
            wrong.write_text(
                '#define TARGET_LAYOUT_IMAGE_SHA256 "' + "0" * 64 + '"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ProfileError, "target layout Image hash mismatch"
            ):
                validate_target_layout(profile, wrong)


if __name__ == "__main__":
    unittest.main()
