# Compatibility

## Supported profile

Version 0.1.0 accepts one profile:

| Field | Required value |
| --- | --- |
| Profile ID | `humane-aipin-45.20-nov4` |
| Manifest | `profiles/humane-45.20/profile.json` |
| Product | Humane AI Pin retail |
| Build fingerprint | `qti/atoll/atoll:12/SKQ1.230401.001/101.000470.45.20:user/release-keys` |
| Exact kernel release (`uname -r`) | `4.14.190-perf` |
| Exact kernel version (`uname -v`) | `#1 SMP PREEMPT Mon Nov 4 18:37:23 PST 2024` |
| Exact kernel machine (`uname -m`) | `aarch64` |
| Active slot | `_b` |
| CPU ABI property (`ro.product.cpu.abi`) | `arm64-v8a` |
| Kernel Image SHA-256 | `d4f4e0deb20871fce207f1f095ba1934162081c2f10afaccbb2e6a1e938719fb` |
| Minimal symbols SHA-256 | `b6bc1dccc155de70881b0abfe708a0e3dba626b819dc03d56686ab9c07517f9b` |

The kernel Image hash identifies the private analysis input used to produce the
profile. The runner cannot read the retail boot partition from an unprivileged
ADB shell, so its live executable gates are the complete fingerprint, exact
kernel release, kernel build marker, slot, ABI, UID, SELinux context, and
enforcing state.

The manifest is the host source of truth. Its hash, kernel Image hash, symbols
hash, and allocator geometry are compiled into the payload. The runner rejects
a stale or substituted manifest, symbol list, or payload before execution. A
separate layout hash beside the hardcoded kernel offsets prevents a manifest
for another Image from silently reusing this target implementation.

The build fingerprint is a userspace property and does not prove that both A/B
boot slots contain the same kernel. Never remove the slot or kernel gate merely
because the fingerprint matches.

If slot `_a` is proven to boot this exact Image, support can be added to the
existing manifest only after a clean-boot physical replay. If it boots a
different Image, it needs a new target project with independently derived
symbols, offsets, geometry, and replay evidence.

## Explicitly unsupported

- slot `_a`;
- userdebug, engineering, or test-key builds;
- any build other than `101.000470.45.20`;
- devices that merely share the Qualcomm `atoll` platform;
- an ADB daemon already running as root;
- a boot where SELinux is already permissive;
- a boot that already has an active root broker or attempt marker.

The developer unit used during research was useful for diagnostics. It is not
part of the public compatibility claim.

## Adding a profile

A new kernel profile requires an independently obtained, lawfully analyzed
Image, a unique target project, and a clean-boot physical replay. A version
string or offset guess is insufficient. Another validated slot for the same
Image extends the existing manifest rather than creating an overlapping
profile.

The implementation sequence is:

1. Create the target project and derive its Image-specific offsets.
2. Add the minimal consumed symbols and record their SHA-256.
3. Add a strict `profile.json` with the exact live identity and allocator
   geometry.
4. Bind `TARGET_LAYOUT_IMAGE_SHA256` to the analyzed Image.
5. Add host regressions for nearby releases, profile ambiguity, and hash drift.
6. Run `./scripts/verify-release.sh` and complete a clean-boot physical replay
   before changing the public support claim.

Submit profile work without firmware, boot images, full symbol tables,
bugreports, device serials, or live addresses. Include:

- the public fingerprint and kernel build string;
- the kernel Image SHA-256;
- the minimal consumed-symbol list;
- allocator geometry;
- host-test results;
- the number of clean-boot physical attempts and successes.
