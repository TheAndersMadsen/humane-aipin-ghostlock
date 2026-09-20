/* SPDX-License-Identifier: Apache-2.0 */
#ifndef GHOSTLOCK_PROFILE_GEOMETRY_H
#define GHOSTLOCK_PROFILE_GEOMETRY_H

#include <stdint.h>

#include "offset.h"

static inline int ghostlock_profile_mm_geometry_matches(
    uint64_t object_size, uint64_t slab_size, uint64_t order,
    uint64_t objects_per_slab, uint64_t cpu_partial) {
  return object_size == PROFILE_MM_OBJECT_SIZE &&
         slab_size == PROFILE_MM_SLAB_SIZE && order == PROFILE_MM_ORDER &&
         objects_per_slab == PROFILE_MM_OBJECTS_PER_SLAB &&
         cpu_partial == PROFILE_MM_CPU_PARTIAL;
}

#endif
