# SPDX-License-Identifier: Apache-2.0
## Modified for the Humane AI Pin port: pin the verified toolchain and make the
## device-specific target the default.  Original work: NebuSec/CyberMeowfia.
API := 35
PROJECT ?= humane-aipin-45.20
OUTDIR ?= build/$(PROJECT)/bin
EMBEDDIR ?= build/embed

TARGET_DIR := src/targets/$(PROJECT)
TARGET_HEADER := $(TARGET_DIR)/target.h

ifeq ($(wildcard $(TARGET_HEADER)),)
$(error unknown PROJECT=$(PROJECT), missing $(TARGET_HEADER))
endif

define pick_src
$(if $(wildcard $(TARGET_DIR)/$(1)),$(TARGET_DIR)/$(1),src/$(1))
endef

EMBED_SU := $(EMBEDDIR)/su_daemon_aarch64_pie
PRELOAD := $(OUTDIR)/preload.so

CORE_SRCS := \
  $(call pick_src,main.c) \
  $(call pick_src,util.c) \
  $(call pick_src,slide.c) \
  $(call pick_src,fops.c) \
  $(call pick_src,pipe.c) \
  src/reclaim_hold.c \
  src/perf_reclaim_math.c \
  src/perf_reclaim_gate.c \
  src/slide_supervisor.c
PRELOAD_SRCS := $(CORE_SRCS) $(call pick_src,preload.c) src/su_blob.S

.DEFAULT_GOAL := preload

PINNED_NDK_VERSION := 28.2.13676358
DARWIN_NDK_ROOT := $(HOME)/Library/Android/sdk/ndk/$(PINNED_NDK_VERSION)
LINUX_NDK_ROOT := $(HOME)/Android/Sdk/ndk/$(PINNED_NDK_VERSION)
NDK_ROOT ?= $(or $(ANDROID_NDK_HOME),$(ANDROID_NDK_ROOT),$(wildcard $(DARWIN_NDK_ROOT)),$(wildcard $(LINUX_NDK_ROOT)))
NDK_PREBUILT := $(if $(filter Darwin,$(shell uname -s)),darwin-x86_64,linux-x86_64)
NDK_TOOLCHAIN ?= $(if $(NDK_ROOT),$(NDK_ROOT)/toolchains/llvm/prebuilt/$(NDK_PREBUILT))
NDK_CC := $(NDK_TOOLCHAIN)/bin/aarch64-linux-android$(API)-clang
HOST_CLANG ?= clang
HOST_CC ?= cc
SHA256 ?= $(shell command -v sha256sum >/dev/null 2>&1 && echo sha256sum || echo "shasum -a 256")
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

ifneq ($(origin CC),default)
  TARGET_CC := $(CC)
  TARGET_FLAGS :=
  TARGET_COMMON_LDFLAGS :=
  TARGET_PIE_LDFLAGS :=
else ifneq ($(wildcard $(NDK_CC)),)
  NDK_CC_WORKS := $(shell $(NDK_CC) --version >/dev/null 2>&1 && echo yes)
  ifeq ($(NDK_CC_WORKS),yes)
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
TARGET_CFLAGS := -DTARGET_CONFIG_H=\"targets/$(PROJECT)/target.h\"

.PHONY: all preload test clean info list-projects

all: preload

preload: $(PRELOAD)

$(OUTDIR):
	mkdir -p $@

$(EMBEDDIR):
	mkdir -p $@

$(EMBED_SU): $(call pick_src,su_daemon.c) | $(EMBEDDIR)
	$(TARGET_CC) $(TARGET_FLAGS) $(PIE_CFLAGS) $(TARGET_CFLAGS) \
	  $< $(TARGET_PIE_LDFLAGS) -o $@

$(PRELOAD): $(PRELOAD_SRCS) $(EMBED_SU) $(TARGET_HEADER) src/offset.h src/kernelsnitch/*.h | $(OUTDIR)
	$(TARGET_CC) $(TARGET_FLAGS) $(SO_CFLAGS) $(WARN_CFLAGS) $(TARGET_CFLAGS) \
	  $(PRELOAD_SRCS) $(TARGET_COMMON_LDFLAGS) \
	  -shared -o $@ -pthread
	$(SHA256) $@

build/tests:
	mkdir -p $@

build/tests/perf_reclaim_gate_test: tests/perf_reclaim_gate_test.c src/perf_reclaim_math.c src/perf_reclaim_gate.h | build/tests
	$(HOST_CC) -std=c11 -O2 -Wall -Wextra -Werror -Isrc $(TARGET_CFLAGS) tests/perf_reclaim_gate_test.c src/perf_reclaim_math.c -o $@

build/tests/reclaim_hold_test: tests/reclaim_hold_test.c src/reclaim_hold.c src/reclaim_hold.h | build/tests
	$(HOST_CC) -std=c11 -O2 -Wall -Wextra -Werror -Isrc tests/reclaim_hold_test.c src/reclaim_hold.c -o $@

build/tests/slide_supervisor_host_test: tests/slide_supervisor_host_test.c src/slide_supervisor.c src/slide_supervisor.h | build/tests
	$(HOST_CC) -std=c11 -O2 -Wall -Wextra -Werror -I. tests/slide_supervisor_host_test.c src/slide_supervisor.c -o $@

test: build/tests/perf_reclaim_gate_test build/tests/reclaim_hold_test build/tests/slide_supervisor_host_test
	./build/tests/perf_reclaim_gate_test
	./build/tests/reclaim_hold_test
	./build/tests/slide_supervisor_host_test

info:
	@echo "PROJECT=$(PROJECT)"
	@echo "TARGET_DIR=$(TARGET_DIR)"
	@echo "TARGET_CC=$(TARGET_CC)"
	@echo "TARGET_FLAGS=$(TARGET_FLAGS)"
	@echo "TARGET_COMMON_LDFLAGS=$(TARGET_COMMON_LDFLAGS)"
	@echo "TARGET_PIE_LDFLAGS=$(TARGET_PIE_LDFLAGS)"
	@echo "PRELOAD=$(PRELOAD)"
	@echo "EMBED_SU=$(EMBED_SU)"
	@echo "CORE_SRCS=$(CORE_SRCS)"

list-projects:
	@find src/targets -mindepth 2 -maxdepth 2 -name target.h -printf '%h\n' | sed 's#src/targets/##' | sort

clean:
	rm -rf build
