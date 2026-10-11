CC ?= cc
OBJDUMP ?= objdump
CFLAGS ?= -O2 -Wall -Wextra -Werror -pedantic
CPPFLAGS ?=
BUILD_DIR := build
INCLUDE_DIR := include
LIB := $(BUILD_DIR)/libpsp_nullifier.so
TEST_BIN := $(BUILD_DIR)/test_nullifier_v1
TIMING_BIN := $(BUILD_DIR)/timing_probe_v1
DISASM := $(BUILD_DIR)/nullifier_v1.disasm.txt

.PHONY: all test audit timing timing-probe-build clean
all: $(LIB)

$(BUILD_DIR):
	mkdir -p $@

$(LIB): nullifier_v1.c $(INCLUDE_DIR)/psp_nullifier_v1.h | $(BUILD_DIR)
	$(CC) -std=c11 $(CFLAGS) $(CPPFLAGS) -fPIC -shared -I$(INCLUDE_DIR) nullifier_v1.c -lcrypto -o $@

$(TEST_BIN): nullifier_v1.c tests/test_nullifier_v1.c $(INCLUDE_DIR)/psp_nullifier_v1.h | $(BUILD_DIR)
	$(CC) -std=c11 $(CFLAGS) $(CPPFLAGS) -I$(INCLUDE_DIR) nullifier_v1.c tests/test_nullifier_v1.c -lcrypto -o $@

$(TIMING_BIN): nullifier_v1.c tests/timing_probe_v1.c $(INCLUDE_DIR)/psp_nullifier_v1.h | $(BUILD_DIR)
	$(CC) -std=c11 $(CFLAGS) $(CPPFLAGS) -I$(INCLUDE_DIR) nullifier_v1.c tests/timing_probe_v1.c -lcrypto -lm -o $@

timing-probe-build: $(TIMING_BIN)
	@printf 'Built preliminary timing probe; not a constant-time certification.\\n'

test: $(LIB) $(TEST_BIN)
	./$(TEST_BIN)

audit: $(LIB)
	$(OBJDUMP) -d -Mintel $(LIB) > $(DISASM)
	@printf 'Wrote optimized wrapper disassembly to %s\n' $(DISASM)
	@printf 'WARNING: wrapper disassembly does not inspect OpenSSL internals or prove constant-time execution.\n'

timing: $(TIMING_BIN)
	./$(TIMING_BIN)

clean:
	rm -rf $(BUILD_DIR)
