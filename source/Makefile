API ?= 35
PROJECT ?= humane-aipin-45.20
OUTDIR ?= build/$(PROJECT)/bin
EMBEDDIR ?= build/embed
PROFILE_MANIFEST ?= ../profiles/humane-45.20/profile.json
TARGET_HEADER ?= src/targets/$(PROJECT)/target.h
GENERATED_DIR := build/$(PROJECT)/generated
PROFILE_HEADER := $(GENERATED_DIR)/ghostlock_profile_generated.h

EMBED_SU := $(EMBEDDIR)/su_daemon_aarch64_pie
PRELOAD := $(OUTDIR)/preload.so
FUTEX_PROBE := $(OUTDIR)/futex_transition_probe
PSELECT_PROBE := $(OUTDIR)/pselect_result_probe

CORE_SRCS := \
	  src/profile_binding.c \
	  src/main.c \
	  src/util.c \
	  src/cred_followup.c \
	  src/reclaim_hold.c \
	  src/reclaim_capture_gate.c \
	  src/perf_reclaim_math.c \
	  src/perf_reclaim_gate.c \
	  src/slide.c \
	  src/slide_supervisor.c \
	  src/fops.c \
	  src/pipe.c
PRELOAD_SRCS := $(CORE_SRCS) src/preload.c src/su_blob.S

.DEFAULT_GOAL := preload

DEFAULT_NDK_ROOT := $(HOME)/android-ndk-cache/android-ndk-r29
DARWIN_NDK_ROOT := $(lastword $(sort $(wildcard $(HOME)/Library/Android/sdk/ndk/*)))
NDK_ROOT ?= $(or $(ANDROID_NDK_HOME),$(ANDROID_NDK_ROOT),$(wildcard $(DEFAULT_NDK_ROOT)),$(DARWIN_NDK_ROOT))
NDK_PREBUILT := $(if $(filter Darwin,$(shell uname -s)),darwin-x86_64,linux-x86_64)
NDK_TOOLCHAIN ?= $(if $(NDK_ROOT),$(NDK_ROOT)/toolchains/llvm/prebuilt/$(NDK_PREBUILT))
NDK_CC := $(NDK_TOOLCHAIN)/bin/aarch64-linux-android$(API)-clang
HOST_CLANG ?= clang
SYSROOT ?= $(if $(NDK_TOOLCHAIN),$(NDK_TOOLCHAIN)/sysroot)
RESOURCE_DIR ?= $(if $(NDK_TOOLCHAIN),$(NDK_TOOLCHAIN)/lib/clang/21)

HOST_TARGET_FLAGS := \
  --target=aarch64-linux-android$(API) \
  --sysroot=$(SYSROOT) \
  -resource-dir $(RESOURCE_DIR) \
  --rtlib=compiler-rt \
  --unwindlib=none
HOST_COMMON_LDFLAGS := \
  -fuse-ld=lld \
  -Wl,-rpath-link,$(SYSROOT)/usr/lib/aarch64-linux-android/$(API) \
  -L$(SYSROOT)/usr/lib/aarch64-linux-android/$(API) \
  -L$(SYSROOT)/usr/lib/aarch64-linux-android
HOST_PIE_LDFLAGS := \
  $(HOST_COMMON_LDFLAGS) \
  -Wl,-dynamic-linker,/system/bin/linker64

ifneq ($(strip $(NDK_ROOT)),)
  TARGET_CC := $(NDK_CC)
  TARGET_FLAGS :=
  TARGET_COMMON_LDFLAGS :=
  TARGET_PIE_LDFLAGS :=
else
  TARGET_CC := $(HOST_CLANG)
  TARGET_FLAGS := $(HOST_TARGET_FLAGS)
  TARGET_COMMON_LDFLAGS := $(HOST_COMMON_LDFLAGS)
  TARGET_PIE_LDFLAGS := $(HOST_PIE_LDFLAGS)
endif

COMMON_CFLAGS := -O2 -g0 -Wall -Wextra -Isrc
PIE_CFLAGS := -fPIE -pie $(COMMON_CFLAGS)
SO_CFLAGS := -fPIC $(COMMON_CFLAGS)
WARN_CFLAGS := -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function
TARGET_CFLAGS := -DTARGET_CONFIG_H=\"$(abspath $(TARGET_HEADER))\" -include $(PROFILE_HEADER)
HOST_TARGET_CFLAGS := -DTARGET_CONFIG_H=\"$(abspath $(TARGET_HEADER))\"

HOST_CC ?= cc
HOST_TEST_DIR := build/host-tests
HOST_TESTS := \
	$(HOST_TEST_DIR)/cred_followup_test \
	$(HOST_TEST_DIR)/perf_reclaim_gate_test \
	$(HOST_TEST_DIR)/reclaim_capture_gate_test \
	$(HOST_TEST_DIR)/reclaim_hold_test \
	$(HOST_TEST_DIR)/slide_supervisor_host_test

.PHONY: all preload futex-probe pselect-probe test clean info

all: preload

preload: $(TARGET_HEADER) $(PROFILE_HEADER) $(PRELOAD)

futex-probe: $(FUTEX_PROBE)

pselect-probe: $(PSELECT_PROBE)

$(TARGET_HEADER):
	@echo "missing $@; generate it from boot.img before building" >&2
	@false

$(PROFILE_HEADER): $(PROFILE_MANIFEST) $(TARGET_HEADER) ../scripts/generate_profile_header.py ../ghostlock_profile.py
	mkdir -p $(GENERATED_DIR)
	python3 ../scripts/generate_profile_header.py \
	  --profile "$(PROFILE_MANIFEST)" --project "$(PROJECT)" \
	  --target-header "$(TARGET_HEADER)" --output "$@"

$(OUTDIR):
	mkdir -p $@

$(EMBEDDIR):
	mkdir -p $@

$(EMBED_SU): src/su_daemon.c | $(EMBEDDIR)
	$(TARGET_CC) $(TARGET_FLAGS) $(PIE_CFLAGS) $(TARGET_CFLAGS) \
	  $< $(TARGET_PIE_LDFLAGS) -o $@

$(PRELOAD): $(PRELOAD_SRCS) $(EMBED_SU) $(TARGET_HEADER) $(PROFILE_HEADER) src/offset.h src/common.h src/kernelsnitch/*.h | $(OUTDIR)
	$(TARGET_CC) $(TARGET_FLAGS) $(SO_CFLAGS) $(WARN_CFLAGS) $(TARGET_CFLAGS) \
	  $(PRELOAD_SRCS) $(TARGET_COMMON_LDFLAGS) \
	  -shared -o $@ -pthread
	sha256sum $@

$(FUTEX_PROBE): tools/futex_transition_probe.c | $(OUTDIR)
	$(TARGET_CC) $(TARGET_FLAGS) $(PIE_CFLAGS) \
	  $< $(TARGET_PIE_LDFLAGS) -pthread -o $@
	sha256sum $@

$(PSELECT_PROBE): tools/pselect_result_probe.c | $(OUTDIR)
	$(TARGET_CC) $(TARGET_FLAGS) $(PIE_CFLAGS) \
	  $< $(TARGET_PIE_LDFLAGS) -o $@
	sha256sum $@

$(HOST_TEST_DIR):
	mkdir -p $@

$(HOST_TEST_DIR)/cred_followup_test: tests/cred_followup_test.c src/cred_followup.c src/cred_followup.h | $(HOST_TEST_DIR)
	$(HOST_CC) -O2 -Wall -Wextra -Isrc $< src/cred_followup.c -o $@

$(HOST_TEST_DIR)/perf_reclaim_gate_test: tests/perf_reclaim_gate_test.c src/perf_reclaim_math.c src/perf_reclaim_gate.h $(TARGET_HEADER) | $(HOST_TEST_DIR)
	$(HOST_CC) -O2 -Wall -Wextra -Isrc $(HOST_TARGET_CFLAGS) $< src/perf_reclaim_math.c -o $@

$(HOST_TEST_DIR)/reclaim_capture_gate_test: tests/reclaim_capture_gate_test.c src/reclaim_capture_gate.c src/reclaim_capture_gate.h | $(HOST_TEST_DIR)
	$(HOST_CC) -O2 -Wall -Wextra -Isrc $< src/reclaim_capture_gate.c -o $@

$(HOST_TEST_DIR)/reclaim_hold_test: tests/reclaim_hold_test.c src/reclaim_hold.c src/reclaim_hold.h | $(HOST_TEST_DIR)
	$(HOST_CC) -O2 -Wall -Wextra -Isrc $< src/reclaim_hold.c -o $@

$(HOST_TEST_DIR)/slide_supervisor_host_test: tests/slide_supervisor_host_test.c src/slide_supervisor.c src/slide_supervisor.h | $(HOST_TEST_DIR)
	$(HOST_CC) -O2 -Wall -Wextra -I. $< src/slide_supervisor.c -o $@

test: $(HOST_TESTS)
	@set -e; for test_binary in $(HOST_TESTS); do "$$test_binary"; done

info:
	@echo "TARGET_HEADER=$(TARGET_HEADER)"
	@echo "PROFILE_HEADER=$(PROFILE_HEADER)"
	@echo "TARGET_CC=$(TARGET_CC)"
	@echo "TARGET_FLAGS=$(TARGET_FLAGS)"
	@echo "TARGET_COMMON_LDFLAGS=$(TARGET_COMMON_LDFLAGS)"
	@echo "TARGET_PIE_LDFLAGS=$(TARGET_PIE_LDFLAGS)"
	@echo "PRELOAD=$(PRELOAD)"
	@echo "FUTEX_PROBE=$(FUTEX_PROBE)"
	@echo "PSELECT_PROBE=$(PSELECT_PROBE)"
	@echo "EMBED_SU=$(EMBED_SU)"
	@echo "CORE_SRCS=$(CORE_SRCS)"

clean:
	rm -rf build
