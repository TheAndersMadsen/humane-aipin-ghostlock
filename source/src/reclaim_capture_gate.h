#ifndef GHOSTLOCK_RECLAIM_CAPTURE_GATE_H
#define GHOSTLOCK_RECLAIM_CAPTURE_GATE_H

#include <stdint.h>

/*
 * Optional one-shot host gate between a held reclaim spray and the first
 * GhostLock trigger.  Configuration is read from:
 *
 *   AI_PIN_RECLAIM_GATE_CONTROL
 *   AI_PIN_RECLAIM_GATE_STATUS
 *   AI_PIN_RECLAIM_GATE_TOKEN
 *   AI_PIN_RECLAIM_GATE_TIMEOUT_MS (optional, default 120000)
 *
 * When disabled, init succeeds and enabled returns false.  Partial or unsafe
 * configuration fails closed.
 */
int ghostlock_capture_gate_init(void);
int ghostlock_capture_gate_enabled(void);
const char *ghostlock_capture_gate_token(void);
int ghostlock_capture_gate_wait(uintptr_t page_base);
void ghostlock_capture_gate_close(void);

#endif
