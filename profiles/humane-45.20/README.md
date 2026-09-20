# Humane 45.20 profile

This directory contains the strict compatibility manifest and minimal
link-time symbol set needed to validate current-boot bugreport anchors. It is
not a device `/proc/kallsyms` dump.

The profile corresponds to the exact kernel Image identified by SHA-256
`d4f4e0deb20871fce207f1f095ba1934162081c2f10afaccbb2e6a1e938719fb`
and the compatibility boundary in [COMPATIBILITY.md](../../docs/COMPATIBILITY.md).

`profile.json` binds the live fingerprint, exact kernel release, version and
machine, accepted slot and ABI, allocator geometry, Image hash, and symbols
hash. The generated native header and host runner both consume this manifest.

Do not add unrelated symbols, runtime addresses, serials, or raw extraction
artifacts.
