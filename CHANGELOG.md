# Changelog

## Unreleased

- Centralize exact compatibility data in strict, hash-bound profile manifests.
- Bind host checks, native preflight, symbols, allocator geometry, and payloads
  to one profile while preserving slot `_b` as the only replayed target.
- Add macOS host CI, serial-redacted check diagnostics, and clearer report
  errors.

## 0.1.0 - 2026-09-20

- Add the exact Humane AI Pin retail 45.20 slot-`_b` profile.
- Add guarded current-boot KASLR derivation and same-PFN reclaim verification.
- Add supervised one-shot kernel write routing.
- Add a boot-scoped, shell-peer-restricted root command broker.
- Add the user-facing `check`, `run`, `verify`, `build`, and `report`
  workflows.
- Add privacy redaction, release audits, host tests, and reproducible-build
  verification.
