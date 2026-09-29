// SPDX-License-Identifier: Apache-2.0
// New GhostLock code; see docs/PROVENANCE.md.

#include "cred_followup.h"

#include <assert.h>

static void test_repair_only(void) {
  struct ghostlock_cred_followup state;
  ghostlock_cred_followup_init(&state, 0);
  assert(ghostlock_cred_followup_next(&state) ==
         GHOSTLOCK_CRED_FOLLOWUP_REPAIR);
  assert(!ghostlock_cred_followup_note(
      &state, GHOSTLOCK_CRED_FOLLOWUP_SELINUX, 1, 1));
  assert(!ghostlock_cred_followup_note(
      &state, GHOSTLOCK_CRED_FOLLOWUP_REPAIR, 0, 1));
  assert(ghostlock_cred_followup_note(
      &state, GHOSTLOCK_CRED_FOLLOWUP_REPAIR, 1, 1));
  assert(ghostlock_cred_followup_next(&state) ==
         GHOSTLOCK_CRED_FOLLOWUP_COMPLETE);
}

static void test_repair_precedes_selinux(void) {
  struct ghostlock_cred_followup state;
  ghostlock_cred_followup_init(&state, 1);
  assert(ghostlock_cred_followup_next(&state) ==
         GHOSTLOCK_CRED_FOLLOWUP_REPAIR);
  assert(ghostlock_cred_followup_note(
      &state, GHOSTLOCK_CRED_FOLLOWUP_REPAIR, 1, 1));
  assert(ghostlock_cred_followup_next(&state) ==
         GHOSTLOCK_CRED_FOLLOWUP_SELINUX);
  assert(!ghostlock_cred_followup_note(
      &state, GHOSTLOCK_CRED_FOLLOWUP_SELINUX, 1, 0));
  assert(ghostlock_cred_followup_next(&state) ==
         GHOSTLOCK_CRED_FOLLOWUP_SELINUX);
  assert(ghostlock_cred_followup_note(
      &state, GHOSTLOCK_CRED_FOLLOWUP_SELINUX, 1, 1));
  assert(ghostlock_cred_followup_next(&state) ==
         GHOSTLOCK_CRED_FOLLOWUP_COMPLETE);
}

int main(void) {
  test_repair_only();
  test_repair_precedes_selinux();
  return 0;
}
