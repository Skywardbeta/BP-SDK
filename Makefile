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
# Public API headers live in include/bp_sdk/ (the consumer contract); module
# sources and their private headers live under src/ (core/ bundle/ transport/
# session/ bpsec/ and adapters/ with adapters/ion, adapters/ud3tn). Every
# module dir plus include/bp_sdk are on the include path, so #include "bp_x.h"
# resolves from anywhere in the tree.
#
# Tested on Linux (gcc), macOS (clang), and Windows (MinGW-w64 / MSYS2).

CC      ?= gcc
AR      ?= ar

PUBLIC_INC = include/bp_sdk
MODULES  = src/core src/bundle src/transport src/session src/bpsec \
           src/adapters src/adapters/ion src/adapters/ud3tn
INCLUDES = -I$(PUBLIC_INC) $(addprefix -I,$(MODULES)) -Itests
CFLAGS   = $(INCLUDES) -Wall -Wextra -std=c11 -O2
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
    src/core/bp_sdk.c src/core/bp_utils.c src/core/bp_cbor.c \
    src/bundle/bp_bundle.c src/bundle/bp_admin.c src/bundle/bp_fragment.c src/bundle/bp_stream.c \
    src/transport/bp_tcpcl.c src/transport/bp_storage.c \
    src/transport/bp_backend_posix.c src/transport/bp_backend_bpsocket.c \
    src/session/bp_session.c src/session/bp_security_intent.c \
    src/bpsec/bp_bpsec.c src/bpsec/bp_bpsec_keys.c src/bpsec/bp_bpsec_policy.c \
    src/bpsec/bp_crypto_backend.c src/bpsec/bp_key_provider.c \
    src/adapters/bp_adapter.c \
    src/adapters/ion/bp_adapter_ion.c src/adapters/ion/bp_ion_policy.c \
    src/adapters/ud3tn/bp_adapter_ud3tn.c src/adapters/ud3tn/bp_aap.c

OBJS = $(addprefix $(BUILD)/,$(notdir $(LIB_SRCS:.c=.o)))

TEST_SRCS = \
    tests/integration/test_phase1.c tests/integration/test_phase2.c \
    tests/integration/test_phase3a.c tests/integration/test_concurrency.c \
    tests/bpsec/test_bpsec_primitives.c \
    tests/session/test_session.c tests/session/test_intent.c \
    tests/adapters/test_facade.c \
    tests/adapters/ion/test_ion_policy.c \
    tests/adapters/ud3tn/test_aap.c \
    tests/adapters/ud3tn/test_ud3tn_adapter.c
TEST_BINS = $(addprefix $(BUILD)/,$(notdir $(TEST_SRCS:.c=$(EXE))))

EXAMPLES = hello_send sender receiver secure_send secure_intent secure_link
EXAMPLE_BINS = $(EXAMPLES:%=$(BUILD)/%$(EXE))

vpath %.c $(MODULES) tests/integration tests/bpsec tests/session \
          tests/adapters tests/adapters/ion tests/adapters/ud3tn

.PHONY: all lib tests test examples clean debug install help

all: lib tests examples

lib: $(LIB)

$(BUILD):
	mkdir -p $(BUILD)

$(LIB): $(BUILD) $(OBJS)
	$(AR) rcs $@ $(OBJS)

$(BUILD)/%.o: %.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

tests: lib $(TEST_BINS)

$(BUILD)/test_%$(EXE): test_%.c $(LIB)
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
	install -m 644 $(PUBLIC_INC)/*.h $(PREFIX)/include/bp_sdk/

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
