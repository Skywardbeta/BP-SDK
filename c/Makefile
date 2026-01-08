# BP-SDK Makefile - Cross-Platform Build
#
# Usage:
#   make          - Build library and tests
#   make lib      - Build library only  
#   make tests    - Build tests only
#   make clean    - Remove build artifacts
#   make test     - Run all tests
#
# Works on: Linux (gcc), macOS (clang), Windows (MinGW-w64/MSYS2)

CC      ?= gcc
AR      ?= ar
CFLAGS   = -I./include -Wall -Wextra -std=c11 -O2
LDFLAGS  =

BUILD    = build
LIB      = $(BUILD)/libbp_sdk.a

# Platform-specific settings
ifeq ($(OS),Windows_NT)
    EXE = .exe
    LDFLAGS += -lws2_32
else
    EXE =
    UNAME := $(shell uname -s)
    ifneq ($(UNAME),Darwin)
        LDFLAGS += -lpthread
    endif
endif

# Core library sources
SRCS = bp_sdk.c bp_utils.c bp_cbor.c bp_bundle.c bp_tcpcl.c \
       bp_bpsec.c bp_bpsec_keys.c bp_bpsec_policy.c \
       bp_fragment.c bp_storage.c bp_admin.c bp_stream.c

BACKEND_SRCS = bp_backend_posix.c bp_backend_bpsocket.c

OBJS = $(SRCS:%.c=$(BUILD)/%.o) $(BACKEND_SRCS:%.c=$(BUILD)/%.o)

# Test executables  
TESTS = test_phase1 test_phase2 test_phase3a test_concurrency
TEST_BINS = $(TESTS:%=$(BUILD)/%$(EXE))

.PHONY: all lib tests test clean debug help

all: lib tests

lib: $(LIB)

$(BUILD):
	mkdir -p $(BUILD)

$(LIB): $(BUILD) $(OBJS)
	$(AR) rcs $@ $(OBJS)

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/%.o: src/backend/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

tests: lib $(TEST_BINS)

$(BUILD)/test_%$(EXE): tests/test_%.c $(LIB)
	$(CC) $(CFLAGS) $< -L$(BUILD) -lbp_sdk $(LDFLAGS) -o $@

test: tests
	@echo ""
	@echo "=== BP-SDK Test Suite ==="
	@for t in $(TEST_BINS); do echo "Running $$t..."; $$t || exit 1; done
	@echo ""
	@echo "=== All tests passed ==="

clean:
	rm -rf $(BUILD)

debug: CFLAGS += -g -O0 -DDEBUG
debug: clean all

# Unix install
PREFIX ?= /usr/local
install: lib
	install -d $(PREFIX)/lib $(PREFIX)/include/bp_sdk
	install -m 644 $(LIB) $(PREFIX)/lib/
	install -m 644 include/*.h $(PREFIX)/include/bp_sdk/

help:
	@echo "BP-SDK Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all     - Build library and tests (default)"
	@echo "  lib     - Build static library"
	@echo "  tests   - Build test executables"
	@echo "  test    - Run all tests"
	@echo "  clean   - Remove build directory"
	@echo "  debug   - Debug build with symbols"
	@echo "  install - Install to PREFIX (default: /usr/local)"
