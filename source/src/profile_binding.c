#include <stddef.h>

/* Keep the complete profile identity in the payload for host-side binding. */
__attribute__((used, visibility("default")))
const char ghostlock_profile_manifest_sha256[] = PROFILE_MANIFEST_SHA256;

__attribute__((used, visibility("default")))
const char ghostlock_kernel_image_sha256[] = TARGET_KERNEL_IMAGE_SHA256;

__attribute__((used, visibility("default")))
const char ghostlock_profile_symbols_sha256[] = PROFILE_SYMBOLS_SHA256;

__attribute__((used, visibility("default")))
const char ghostlock_profile_id[] = BUILD_VARIANT_LABEL;
