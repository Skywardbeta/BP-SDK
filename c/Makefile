# BP-SDK Makefile

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -O2 -fPIC
INCLUDES = -I./include -I../bpv7/include -I../ici/include -I../ici/sdr
LIBS = -pthread -lm -lssl -lcrypto

# Directories
SRC_DIR = src
INCLUDE_DIR = include
EXAMPLES_DIR = examples
TEST_DIR = test
BUILD_DIR = build
LIB_DIR = lib

# Sources and objects
SOURCES = $(SRC_DIR)/bp_sdk_core.c $(SRC_DIR)/bp_sdk_cla.c $(SRC_DIR)/bp_sdk_routing.c $(SRC_DIR)/bp_sdk_admin.c $(SRC_DIR)/bp_sdk_security.c
OBJECTS = $(SOURCES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# Libraries and examples
LIBRARY = $(LIB_DIR)/libbp_sdk.so
STATIC_LIBRARY = $(LIB_DIR)/libbp_sdk.a
EXAMPLES = $(BUILD_DIR)/simple_send $(BUILD_DIR)/simple_receive $(BUILD_DIR)/cla_example
TESTS = $(BUILD_DIR)/basic_test $(BUILD_DIR)/bpsec_test

# Default target
all: $(LIBRARY) $(STATIC_LIBRARY) $(EXAMPLES) $(TESTS)

# Create directories
$(BUILD_DIR) $(LIB_DIR):
	mkdir -p $@

# Compile objects
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Create libraries
$(LIBRARY): $(OBJECTS) | $(LIB_DIR)
	$(CC) -shared -o $@ $^ $(LIBS)

$(STATIC_LIBRARY): $(OBJECTS) | $(LIB_DIR)
	ar rcs $@ $^

# Build examples
$(BUILD_DIR)/%: $(EXAMPLES_DIR)/%.c $(LIBRARY)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< -L$(LIB_DIR) -lbp_sdk $(LIBS)

$(BUILD_DIR)/%: $(TEST_DIR)/%.c $(LIBRARY)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< -L$(LIB_DIR) -lbp_sdk $(LIBS)

# Install
install: $(LIBRARY) $(STATIC_LIBRARY)
	install -d /usr/local/lib /usr/local/include/bp_sdk
	install -m 755 $(LIBRARY) /usr/local/lib/
	install -m 644 $(STATIC_LIBRARY) /usr/local/lib/
	install -m 644 $(INCLUDE_DIR)/*.h /usr/local/include/bp_sdk/
	ldconfig

# Uninstall
uninstall:
	rm -f /usr/local/lib/libbp_sdk.so /usr/local/lib/libbp_sdk.a
	rm -rf /usr/local/include/bp_sdk
	ldconfig

# Clean
clean:
	rm -rf $(BUILD_DIR) $(LIB_DIR)

# Test instructions
test: $(TESTS)
	@echo "Running tests:"
	@echo "  Basic: ./$(BUILD_DIR)/basic_test"
	@echo "  BPSEC: ./$(BUILD_DIR)/bpsec_test"
	./$(BUILD_DIR)/basic_test
	./$(BUILD_DIR)/bpsec_test

examples: $(EXAMPLES)
	@echo "Run examples:"
	@echo "  Send: ./$(BUILD_DIR)/simple_send ipn:1.1 ipn:2.1 'Hello'"
	@echo "  Receive: ./$(BUILD_DIR)/simple_receive ipn:2.1"
	@echo "  CLA: ./$(BUILD_DIR)/cla_example 127.0.0.1 4556"

.PHONY: all install uninstall clean test examples 