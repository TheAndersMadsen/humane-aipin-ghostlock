// SPDX-License-Identifier: Apache-2.0
// New GhostLock code; see docs/PROVENANCE.md.

#include "cred_followup.h"

#include <stddef.h>

void ghostlock_cred_followup_init(
    struct ghostlock_cred_followup *state, int require_selinux) {
  if (!state) {
    return;
  }
  state->require_selinux = require_selinux != 0;
  state->repaired = 0;
  state->selinux_disabled = 0;
}

enum ghostlock_cred_followup_step ghostlock_cred_followup_next(
    const struct ghostlock_cred_followup *state) {
  if (!state || !state->repaired) {
    return GHOSTLOCK_CRED_FOLLOWUP_REPAIR;
  }
  if (state->require_selinux && !state->selinux_disabled) {
    return GHOSTLOCK_CRED_FOLLOWUP_SELINUX;
  }
  return GHOSTLOCK_CRED_FOLLOWUP_COMPLETE;
}

int ghostlock_cred_followup_note(
    struct ghostlock_cred_followup *state,
    enum ghostlock_cred_followup_step step, int route_ok, int effect_ok) {
  if (!state || step != ghostlock_cred_followup_next(state) ||
      step == GHOSTLOCK_CRED_FOLLOWUP_COMPLETE) {
    return 0;
  }
  if (!route_ok || !effect_ok) {
    return 0;
  }
  if (step == GHOSTLOCK_CRED_FOLLOWUP_REPAIR) {
    state->repaired = 1;
  } else if (step == GHOSTLOCK_CRED_FOLLOWUP_SELINUX) {
    state->selinux_disabled = 1;
  }
  return 1;
}
