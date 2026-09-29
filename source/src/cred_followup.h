// SPDX-License-Identifier: Apache-2.0
// New GhostLock code; see docs/PROVENANCE.md.

#ifndef GHOSTLOCK_CRED_FOLLOWUP_H
#define GHOSTLOCK_CRED_FOLLOWUP_H

enum ghostlock_cred_followup_step {
  GHOSTLOCK_CRED_FOLLOWUP_REPAIR = 1,
  GHOSTLOCK_CRED_FOLLOWUP_SELINUX = 2,
  GHOSTLOCK_CRED_FOLLOWUP_COMPLETE = 3,
};

struct ghostlock_cred_followup {
  int require_selinux;
  int repaired;
  int selinux_disabled;
};

void ghostlock_cred_followup_init(
    struct ghostlock_cred_followup *state, int require_selinux);
enum ghostlock_cred_followup_step ghostlock_cred_followup_next(
    const struct ghostlock_cred_followup *state);
int ghostlock_cred_followup_note(
    struct ghostlock_cred_followup *state,
    enum ghostlock_cred_followup_step step, int route_ok, int effect_ok);

#endif
