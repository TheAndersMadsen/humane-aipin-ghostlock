# Technical design

This document describes the release architecture without reproducing private
device evidence.

## Vulnerability

CVE-2026-43499 is a local privilege-escalation vulnerability in Linux's
priority-inheritance futex path. A requeue/error sequence can leave
`task->pi_blocked_on` pointing to an `rt_mutex_waiter` that lived on
another thread's kernel stack. When that stack is freed, later priority
adjustment can walk attacker-reclaimed memory.

The stable kernel fix is available from
[kernel.org](https://git.kernel.org/stable/c/838ce5cb5d93c3ab8b27e75bc6ad905a94b752fd).

## Release chain

### 1. Runtime target gate

One strict profile manifest binds the Image hash, minimal symbols, exact live
identity, accepted placements, and allocator geometry. The build generates the
native gate from that manifest and embeds the manifest, Image, and symbols
hashes in the payload. The runner rejects any payload/profile drift.

The payload independently verifies the fingerprint, exact kernel release,
version and machine, active slot, ABI, shell UID, SELinux domain, and enforcing
state. The host runner checks the same boundary before and after bugreport
capture. Immediately before writing the one-attempt marker, it also rechecks
the configured minimum battery level and external power state, then acquires
the boot-specific attempt claim with an atomic directory creation.

### 2. Boot-bound KASLR derivation

The host captures a bugreport synchronously between two device-state samples.
The parser considers only the root bugreport text member and its current live
kernel-log section. It requires at least two independent PC/LR symbol anchors
to yield the same aligned slide.

Archived logcat members are ignored. A pre-existing bugreport additionally
must embed the expected boot ID, serial, and fingerprint.

### 3. `mm_struct` timing leak

KernelSnitch creates contention in selected private-futex hash buckets and
measures wake latency for candidate addresses. The AI Pin port models the
vendor 4.14 private-futex key and the eight-CPU, 2048-bucket hash table. It
repeats candidate verification and searches the profiled direct-map window for
an `mm_struct` address.

### 4. Controlled page reclaim

The target's `mm_struct` cache uses 896-byte slots in an order-3 slab. Child
process lifetimes shape the slab so that closing one process-memory descriptor
releases the page. Unix socket buffers provide the controlled reclaim data.

Before the corruption trigger can run, filtered perf tracepoint counters must
show one matching order-3 free and one matching allocation for the same PFN
candidate. A miss aborts the attempt.

### 5. Waiter overwrite and supervised route

A carefully shaped `pselect6` argument copy occupies the stale waiter's stack
position. A priority update then follows the forged waiter and performs the
required red-black-tree update.

Every write attempt runs in a dedicated child process group. The supervisor
uses a framed result protocol, a monotonic deadline, and process-group cleanup
so a failed child cannot silently continue into a second trigger.

### 6. Read and write primitives

The boot ID sysctl data pointer acts as a bounded read-back oracle. The route
resolves the per-CPU current-task pointer, updates `real_cred` and `cred`,
repairs the credential ID fields, and clears SELinux enforcing. It reloads the
existing policy rather than installing a new policy.

### 7. Boot-scoped command broker

The embedded client is atomically installed under `/data/local/tmp`. The
daemon refuses to start unless all real and effective UID/GID values are zero.
Its Unix socket is owned by root:shell with mode 0660, and each accepted
connection must pass `SO_PEERCRED` with UID 0 or 2000. Requests are bounded
and versioned.

## Fail-closed invariants

- one exploit execution per kernel boot;
- exact target profile and payload hash;
- current-boot KASLR agreement from multiple anchors;
- dynamic allocator geometry must equal the profiled geometry;
- same-PFN free/allocation proof before corruption;
- supervised single-use write children;
- independent fresh-shell root verification;
- privacy-safe monotonic phase durations for failure comparison;
- no persistence, partition write, module load, or network request.

## Limits

The chain remains probabilistic because it depends on timing and allocator
state. The gates are designed to convert uncertainty into a stopped run, not
to guarantee success. A kernel panic or hard hang remains possible after the
vulnerability is triggered.
