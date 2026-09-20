# Safety model

GhostLock crosses a kernel privilege boundary and deliberately exercises a
use-after-free. A correct target profile reduces uncertainty; it does not make
kernel memory corruption safe.

## Before a run

Use a device you own. Back up any data you can access, close unrelated ADB
sessions, connect stable external power, and keep the USB data path physically
stable. Run `./ghostlock check --serial YOUR_SERIAL` immediately before the
attempt.

The check must show:

- the exact supported fingerprint, kernel version, and machine;
- slot `_b`;
- UID 2000 in `u:r:shell:s0`;
- SELinux `Enforcing`;
- an authorized ADB state;
- known battery state and connected external power.

Do not override a failed target gate. A nearby firmware can move every kernel
offset while retaining the same Android and kernel version strings.

## One attempt per boot

Immediately before writing the boot-bound marker, the runner rechecks battery
level and external power using the launcher's `--min-battery` threshold. An
unavailable reading, a low level, or disconnected power stops the run without
consuming the attempt. A threshold of zero explicitly disables this power
gate. The runner then atomically creates a boot-specific claim directory, so
concurrent runners cannot both enter the corruption stage. It never removes a
stale claim while a run is in progress. After the claim is acquired, a second
attempt on the same boot is rejected. Reboot after any failure, disconnect,
timeout, or result you cannot explain.

This rule matters because a failed route may leave allocator or rtmutex state
changed even when user space still appears healthy.

## Hard-hang recovery

A hard hang can stop ADB and the normal reboot path. If this happens:

1. stop issuing ADB commands;
2. disconnect USB and every charger;
3. wait for the internal battery to drain;
4. reconnect power and wait for a normal boot;
5. run `check` again before deciding whether to retry.

The tested retail hardware has no dependable user-accessible forced-restart
combination. Do not improvise with EDL writes, partition flashing, or voltage
injection as part of this PoC.

## Changes made by the PoC

The payload changes credentials and SELinux state in RAM, stages files under
`/data/local/tmp`, and starts a local Unix-socket command broker. It performs
no partition writes and installs no boot persistence.

A reboot is the security boundary that removes live root. Staged files may
remain as inert data until removed by the cleanup command in the README.

## Stop conditions

Stop and reboot if:

- the device disconnects during KASLR capture or exploit execution;
- the runner reports a changed boot identity;
- the payload hash differs after transfer;
- the same-PFN reclaim gate is not verified;
- the root proof is incomplete;
- SELinux or the shell boundary differs from the expected pre-run state.

Do not turn a failed-closed check into a manual command sequence.
