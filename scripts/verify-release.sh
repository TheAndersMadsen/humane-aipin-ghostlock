#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary_dir=$(mktemp -d /tmp/ghostlock-release.XXXXXX)
trap 'rm -rf "$temporary_dir"' EXIT HUP INT TERM

cd "$repo_dir"
python3 scripts/release_audit.py
python3 -m unittest discover -s tools -p 'test_*.py' -v
python3 -m unittest discover -s runner -p 'test_*.py' -v
make -C source test

./ghostlock build
python3 scripts/verify_payload_profile.py \
  --profile profiles/humane-45.20/profile.json \
  --payload source/build/humane-aipin-45.20/bin/preload.so
cp source/build/humane-aipin-45.20/bin/preload.so "$temporary_dir/first.so"
./ghostlock build
cmp "$temporary_dir/first.so" source/build/humane-aipin-45.20/bin/preload.so

git diff --check
echo "release verification passed"
