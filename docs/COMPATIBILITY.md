# Compatibility

## Supported profile

Version 0.1.0 accepts one profile:

| Field | Required value |
| --- | --- |
| Product | Humane AI Pin retail |
| Build fingerprint | `qti/atoll/atoll:12/SKQ1.230401.001/101.000470.45.20:user/release-keys` |
| Kernel release | `Linux version 4.14.190-perf` |
| Kernel build marker | `Mon Nov 4 18:37:23 PST 2024` |
| Active slot | `_b` |
| CPU ABI property (`ro.product.cpu.abi`) | `arm64-v8a` |
| Kernel Image SHA-256 | `d4f4e0deb20871fce207f1f095ba1934162081c2f10afaccbb2e6a1e938719fb` |

The kernel Image hash identifies the private analysis input used to produce the
profile. The runner cannot read the retail boot partition from an unprivileged
ADB shell, so its live executable gates are the complete fingerprint, kernel
markers, slot, ABI, UID, SELinux context, and enforcing state.

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

A new profile requires an independently obtained, lawfully analyzed kernel
Image and a clean-boot physical replay. A version string or offset guess is
insufficient.

Submit profile work without firmware, boot images, full symbol tables,
bugreports, device serials, or live addresses. Include:

- the public fingerprint and kernel build string;
- the kernel Image SHA-256;
- the minimal consumed-symbol list;
- allocator geometry;
- host-test results;
- the number of clean-boot physical attempts and successes.
