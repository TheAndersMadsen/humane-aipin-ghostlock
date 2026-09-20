# Agent Guide

## Scope

GhostLock is a boot-scoped kernel-exploit proof of concept for one exact
Humane AI Pin retail profile. Keep changes narrow, reviewable, and fail-closed.

Before changing target acceptance, read `docs/COMPATIBILITY.md`. A matching
firmware fingerprint or slot name does not establish kernel compatibility.
Support a new kernel or slot only after the exact Image has been profiled and a
clean-boot physical replay has succeeded. Keep guessed offsets and unverified
compatibility claims out of the code and documentation.

## Working map

- `tools/ghostlock.py`: public CLI, device inspection, and compatibility gates.
- `runner/`: production-equivalent orchestration and KASLR extraction.
- `source/`: target payload and host-side native tests.
- `profiles/`: minimal derived symbol inputs for supported kernel Images.
- `docs/SAFETY.md`: device-run procedure, stop conditions, and recovery.
- `docs/PRIVACY.md`: handling and redaction of device evidence.
- `docs/PROVENANCE.md`: source and derivation requirements.

Read the relevant document before changing that area. Keep compatibility
values in sync across the CLI, runner, payload preflight, tests, and public
documentation.

## Workflow

1. Inspect `git status` and preserve unrelated work.
2. Add a host regression test for logic that can be exercised off-device.
3. Run the narrow affected test while iterating.
4. Run `./scripts/verify-release.sh` before declaring a code or release change
   complete. It requires Android NDK `28.2.13676358` and covers the release
   audit, Python tests, native tests, and reproducible payload build.
5. Report the checks actually run. Treat device validation as incomplete until
   it has been performed on a clean boot of the exact accepted profile.

Use `./ghostlock check --serial SERIAL` for read-only device inspection. Follow
`docs/SAFETY.md` before any live exploit attempt. Preserve every preflight
guard and the one-attempt-per-boot rule; turn new uncertainty into a failed
check, not a manual bypass.

## Evidence and repository hygiene

Follow `CONTRIBUTING.md` for profile evidence and review requirements. When
runtime evidence must be shared, run
`./ghostlock report PRIVATE_RUN_DIRECTORY --output ghostlock-report.json`,
then inspect the reduced report manually.

Keep private device artifacts outside the repository. In particular, exclude
firmware and partition images, ADB keys, raw bugreports or logs, serials and
account identifiers, full symbol tables, live addresses, and run directories.
Run `git diff --check` and `git diff --cached --check`, then review the staged
diff before committing.
