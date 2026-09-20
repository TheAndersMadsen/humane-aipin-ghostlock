# Source provenance

## Licensed base

The repository was created from:

- project: [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia);
- component: `IonStack/CVE-2026-43499`;
- commit: `94ae8ab301b2ec9f36bdd66321b6e11209ae60d1`;
- license: Apache License 2.0.

The upstream repository has no root `NOTICE` file at that commit. Its
Apache-2.0 `LICENSE` is preserved at the repository root.

## File map

| Release path | Origin | Local work |
| --- | --- | --- |
| `LICENSE` | CyberMeowfia root license | Unchanged |
| `source/src/kernelsnitch/*` | CyberMeowfia KernelSnitch | Vendor 4.14 futex-key model, bucket count, retry and publication hardening |
| `source/src/offset.h` | CyberMeowfia build indirection | Retained for target selection |
| `source/src/su_blob.S` | CyberMeowfia embedding mechanism | Retained for the rewritten broker |
| `source/src/targets/humane-aipin-45.20/*` | New AI Pin target on the licensed technique | Reimplemented target profile, reclaim route, supervised writes, root path, installer, and broker |
| `source/src/perf_reclaim_*` | New | Same-PFN runtime gate and address math |
| `source/src/reclaim_hold.*` | New | Socket-buffer reclaim ownership |
| `source/src/slide_supervisor.*` | New | Child framing, deadlines, and cleanup |
| `runner/*`, `tools/*`, `scripts/*` | New | Host guardrails, KASLR parser, launcher, redaction, and release audit |
| `docs/*` and project metadata | New | Public documentation and release process |

Modified target files carry SPDX identifiers and modification notices. This
table provides the prominent change notice required by Apache-2.0 section 4.

## Unlicensed prior art

Public AI Pin and Android ports helped establish that CVE-2026-43499 was known
and actively researched. One inspected AI Pin port had no redistribution
license. No commit, file, binary, patch, or Git history from that repository is
included here.

The release was rebuilt in a fresh Git repository from the Apache-2.0 base.
Device-specific files were rewritten, and a normalized four-line source audit
found zero blocks present only in the unlicensed port across the release
target and support modules.

## Private analysis inputs

The exact kernel Image, eMMC dump, full symbol table, decompiler output,
bugreports, and device logs are not part of this repository or its history.
The public profile contains only consumed link-time constants, a minimal
symbol list, public build identifiers, and the kernel Image SHA-256.

## Disclosure status

CVE-2026-43499 was already public before this device port. The CVE record,
stable Linux fix, and multiple public implementations were available. This
project claims a device-specific compatibility result; it does not claim
discovery of the underlying Linux vulnerability.
