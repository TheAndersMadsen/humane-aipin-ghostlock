# Contributing

Contributions should keep the project narrow, reviewable, and fail-closed.

Before opening a pull request:

```sh
./scripts/verify-release.sh
```

For target-profile changes, include the exact public build identifiers, kernel
Image SHA-256, minimal consumed symbols, allocator geometry, and an honest
clean-boot attempt denominator. Do not submit guessed offsets or family-wide
compatibility claims. Follow the profile sequence and unique-project rules in
`docs/COMPATIBILITY.md`.

Never commit firmware, eMMC data, boot images, full symbol tables, bugreports,
run logs, ADB keys, device serials, account data, or live addresses. Generate a
reduced diagnostic with `./ghostlock report` when an issue needs runtime
evidence.

Changes to the corruption route need:

- a clear explanation of the invariant being changed;
- a host regression test when the logic is testable off-device;
- a clean build with the pinned NDK;
- a clean-boot replay on the exact target before a support claim changes.

By contributing, you agree that your contribution is licensed under
Apache-2.0 and that you have the right to submit it.
