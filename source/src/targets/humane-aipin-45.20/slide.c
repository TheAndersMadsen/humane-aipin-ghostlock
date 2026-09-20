/* SPDX-License-Identifier: Apache-2.0 */
#include "common.h"

/* The guarded host runner supplies and boot-binds the KASLR base. */
int slide_leak_kernel_base(void) {
  return kaslr_base != 0 && (kaslr_base & (PAGE_SIZE - 1)) == 0;
}

int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return 10 + c - 'a';
  }
  if (c >= 'A' && c <= 'F') {
    return 10 + c - 'A';
  }
  return -1;
}
