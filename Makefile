# BP-SDK Makefile - Cross-platform build
#
# Usage:
#   make            - Build library, tests, and examples
#   make lib        - Build static library only
#   make tests      - Build test binaries
#   make examples   - Build example binaries
#   make test       - Run the test suite
#   make clean      - Remove build artifacts
#   make debug      - Rebuild with -g -O0 -DDEBUG
#   make install    - Install lib + headers to PREFIX (default /usr/local)
#
# Tested on Linux (gcc), macOS (clang), and Windows (MinGW-w64 / MSYS2).

CC      ?= gcc
AR      ?= ar
CFLAGS   = -I./include -Wall -Wextra -std=c11 -O2
LDFLAGS  =

BUILD    = build
LIB      = $(BUILD)/libbp_sdk.a

ifeq ($(OS),Windows_NT)
    EXE = .exe
    LDFLAGS += -lws2_32 -lbcrypt
else
    EXE =
    UNAME := $(shell uname -s)
    ifneq ($(UNAME),Darwin)
        LDFLAGS += -lpthread
    endif
endif

LIB_SRCS = \
    bp_sdk.c bp_utils.c bp_cbor.c bp_bundle.c \
    bp_tcpcl.c bp_admin.c bp_storage.c bp_fragment.c bp_stream.c \
    bp_bpsec.c bp_bpsec_keys.c bp_bpsec_policy.c \
    bp_crypto_backend.c bp_key_provider.c bp_session.c

BACKEND_SRCS = bp_backend_posix.c bp_backend_bpsocket.c

OBJS = $(LIB_SRCS:%.c=$(BUILD)/%.o) $(BACKEND_SRCS:%.c=$(BUILD)/%.o)

TESTS = test_phase1 test_phase2 test_phase3a test_concurrency \
        test_bpsec_primitives test_session
TEST_BINS = $(TESTS:%=$(BUILD)/%$(EXE))

EXAMPLES = hello_send sender receiver secure_send
EXAMPLE_BINS = $(EXAMPLES:%=$(BUILD)/%$(EXE))

.PHONY: all lib tests test examples clean debug install help

all: lib tests examples

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

examples: lib $(EXAMPLE_BINS)

$(BUILD)/%$(EXE): examples/%.c $(LIB)
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

PREFIX ?= /usr/local
install: lib
	install -d $(PREFIX)/lib $(PREFIX)/include/bp_sdk
	install -m 644 $(LIB) $(PREFIX)/lib/
	install -m 644 include/*.h $(PREFIX)/include/bp_sdk/

help:
	@echo "BP-SDK build targets:"
	@echo "  all       Build library, tests, and examples (default)"
	@echo "  lib       Build static library only"
	@echo "  tests     Build test binaries"
	@echo "  examples  Build example binaries"
	@echo "  test      Run the test suite"
	@echo "  clean     Remove the build/ directory"
	@echo "  debug     Rebuild with debug flags"
	@echo "  install   Install lib + headers to PREFIX (default /usr/local)"
