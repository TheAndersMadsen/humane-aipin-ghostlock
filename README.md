# GhostLock for Humane AI Pin

GhostLock for Humane AI Pin is an open-source, boot-scoped root proof of
concept for one exact retail firmware build. It exercises
[CVE-2026-43499](https://www.cve.org/CVERecord?id=CVE-2026-43499), a Linux
rtmutex use-after-free, from an ordinary authorized ADB shell.

The runner is deliberately narrow. It checks the complete firmware
fingerprint, kernel build, slot, shell UID and SELinux state before it stages
anything. A mismatch stops the run.

> [!WARNING]
> This is a kernel exploit. It can panic, reboot, or hard-hang the Pin. A hard
> hang may require unplugging the device and waiting for the battery to drain.
> Use it only on a Pin you own and can afford to recover. Root disappears on
> reboot.

## Tested target

| Property | Accepted value |
| --- | --- |
| Device | Humane AI Pin, retail unit |
| Firmware | `qti/atoll/atoll:12/SKQ1.230401.001/101.000470.45.20:user/release-keys` |
| Android | 12 |
| Kernel | `4.14.190-perf`, built `Mon Nov 4 18:37:23 PST 2024` |
| Slot | `_b` only |
| Kernel architecture | `aarch64` |
| Android ABI | `arm64-v8a` |
| Profile | `humane-aipin-45.20` |
| Kernel Image SHA-256 | `d4f4e0deb20871fce207f1f095ba1934162081c2f10afaccbb2e6a1e938719fb` |
| Release-candidate replay | Pending final clean-boot replay |

Slot `_a`, developer firmware, nearby firmware versions, and other Qualcomm
`atoll` products are rejected. See [compatibility details](docs/COMPATIBILITY.md).
A matching Android fingerprint is not enough to bypass this check: A/B slots
can carry different boot images and kernel layouts under the same userspace
build identity.

## Before you begin

You need:

- a user-owned Pin already authorized for ADB;
- a stable USB data connection and external power;
- `adb`, Python 3.10 or newer, `make`, and a C compiler;
- Android NDK `28.2.13676358` (r28c) to build the payload.

This repository does not contain an ADB private key, firmware image, boot
image, bugreport, device log, or prebuilt payload.

Install the pinned NDK with Android's command-line tools:

```sh
sdkmanager "ndk;28.2.13676358"
```

Confirm that ADB already sees the Pin as `device`:

```text
$ adb devices
List of devices attached
YOUR_SERIAL    device
```

## Run it

Clone the repository, then use the same explicit serial for every command:

```sh
git clone https://github.com/TheAndersMadsen/humane-aipin-ghostlock.git
cd humane-aipin-ghostlock

./ghostlock check --serial YOUR_SERIAL
./ghostlock run --serial YOUR_SERIAL
./ghostlock verify --serial YOUR_SERIAL
```

`check` is read-only. It prints the detected firmware, kernel, slot, shell
boundary, SELinux state, battery, power source, and NDK revision.

`run` performs one guarded attempt. It asks you to type
`ROOT YOUR_SERIAL`, builds from source, verifies the payload hash after
pushing it, captures a current-boot bugreport to derive KASLR, deletes that raw
bugreport by default, and starts the exploit only after a second complete
preflight.

`verify` independently asks the boot-scoped root broker to run `id` and
`getenforce`.

A successful verification looks like this:

```text
uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0
SELinux: Permissive
Boot epoch: <redacted>; uptime: <redacted>s
```

The exact SELinux context is kernel and firmware specific. The acceptance
condition is UID/GID 0 through the broker with SELinux permissive on the same
boot.

## What the PoC changes

For the current boot, the payload:

1. replaces the exploit process's credential pointers with `init_cred`;
2. clears SELinux enforcing and reloads the current policy;
3. writes a small command client to `/data/local/tmp/su`;
4. starts a Unix-socket broker that accepts only kernel-authenticated UID 0 or
   Android shell UID 2000 peers.

It does not write a partition, unlock the bootloader, install a module, modify
verified boot, create reboot persistence, contact a network service, or upload
telemetry.

Run a root command from another ADB shell with:

```sh
adb -s YOUR_SERIAL shell '/data/local/tmp/su -c id'
```

## Failure and recovery

The runner permits one attempt per kernel boot. If it reports a miss, timeout,
disconnect, uncertain state, panic, or reboot, do not retry on that boot.
Reboot first and run `check` again.

If ADB still responds:

```sh
adb -s YOUR_SERIAL reboot
```

If the Pin is hard-hung and ADB does not respond, disconnect all external
power. The tested retail hardware has no dependable user-accessible forced
restart, so recovery may require waiting for the battery to drain before
reconnecting power.

After a normal reboot, root is gone. The staged files may remain inert under
`/data/local/tmp`; a clean shell can remove them:

```sh
adb -s YOUR_SERIAL shell 'rm -f /data/local/tmp/ghostlock-aipin.so /data/local/tmp/su /data/local/tmp/.ghostlock-su.sock /data/local/tmp/.ghostlock-aipin-attempt'
```

Read [SAFETY.md](docs/SAFETY.md) before using the PoC and
[TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) before retrying a failed run.

## Private logs and issue reports

Run records are written to a mode-0700 temporary directory. They contain a
device serial, boot identity, kernel addresses, and exploit telemetry. Never
attach that directory or a raw Android bugreport to an issue.

Create a reduced report instead:

```sh
./ghostlock report /private/tmp/ghostlock-aipin-TIMESTAMP --output ghostlock-report.json
```

Review the JSON before sharing it. The redactor omits serials, boot IDs, host
paths, raw command output, and kernel addresses. See [PRIVACY.md](docs/PRIVACY.md).

## Build and test

Build the Android payload:

```sh
./ghostlock build
```

Run all host tests and two independent builds:

```sh
./scripts/verify-release.sh
```

The payload is written to:

```text
source/build/humane-aipin-45.20/bin/preload.so
```

Build products are ignored by Git. Release assets should be verified against
the checksums attached to the corresponding GitHub release.

## How it works

The exploit uses the CVE's dangling stack-resident `rt_mutex_waiter` to
route a controlled red-black-tree update. KernelSnitch first leaks an
`mm_struct` address through futex-hash timing. A same-PFN perf-event gate
then proves that the released order-3 slab page was reclaimed by controlled
socket-buffer data before the corruption trigger can proceed. A boot-bound
KASLR base is derived from at least two agreeing current-boot WARN anchors.
The resulting read/write route resolves the current task and performs the
boot-scoped credential change.

The target profile contains only the offsets and symbols consumed by this
route. The kernel Image and full symbol table are not distributed.
[TECHNICAL.md](docs/TECHNICAL.md) describes the stages and fail-closed gates.

## Project status

This is an experimental research release for an unsupported consumer device.
It is not a general Android rooting tool and is not affiliated with Humane,
HP, or CosmOS.

The code is licensed under Apache-2.0. The implementation starts from
NebuSec's Apache-2.0 CyberMeowfia work; the AI Pin port and release tooling are
documented in [PROVENANCE.md](docs/PROVENANCE.md) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Please read [SECURITY.md](SECURITY.md) before reporting a vulnerability or
misuse concern.
