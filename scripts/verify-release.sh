#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary_dir=$(mktemp -d /tmp/ghostlock-release.XXXXXX)
trap 'rm -rf "$temporary_dir"' EXIT HUP INT TERM

cd "$repo_dir"
python3 scripts/release_audit.py
python3 -m unittest discover -s tools -p 'test_*.py' -v
python3 -m unittest discover -s runner -p 'test_*.py' -v

python3 - "$repo_dir" >"$temporary_dir/profiles.tsv" <<'PY'
import sys
from pathlib import Path

repo = Path(sys.argv[1])
sys.path.insert(0, str(repo))

from ghostlock_profile import load_profiles

for profile in load_profiles(repo / "profiles"):
    print(
        profile.profile_id,
        profile.project,
        profile.manifest_path,
        sep="\t",
    )
PY

tab=$(printf '\t')
while IFS="$tab" read -r profile_id project manifest_path; do
  make -C source clean test \
    "PROJECT=$project" "PROFILE_MANIFEST=$manifest_path"
  ./ghostlock build --profile "$profile_id"
  payload="source/build/$project/bin/preload.so"
  python3 scripts/verify_payload_profile.py \
    --profile "$manifest_path" --payload "$payload"
  first_payload="$temporary_dir/$profile_id.first.so"
  cp "$payload" "$first_payload"
  ./ghostlock build --profile "$profile_id"
  cmp "$first_payload" "$payload"
done <"$temporary_dir/profiles.tsv"

git diff --check
echo "release verification passed"
