CC ?= cc
OBJDUMP ?= objdump
CFLAGS ?= -O2 -Wall -Wextra -Werror -pedantic
CPPFLAGS ?=
BUILD_DIR := build
INCLUDE_DIR := include
LIB := $(BUILD_DIR)/libpsp_nullifier.so
TEST_BIN := $(BUILD_DIR)/test_nullifier_v1
TIMING_BIN := $(BUILD_DIR)/timing_probe_v1
TIMING_V2_BIN := $(BUILD_DIR)/timing_probe_v2
SAN_TEST_V1_BIN := $(BUILD_DIR)/test_nullifier_v1_sanitize
SAN_TEST_V2_BIN := $(BUILD_DIR)/test_nullifier_v2_sanitize
V2_TEST_BIN := $(BUILD_DIR)/test_nullifier_v2
DISASM := $(BUILD_DIR)/nullifier_native.disasm.txt

.PHONY: all test audit timing timing-probe-build timing-v2 timing-v2-probe-build sanitize-test clean
all: $(LIB)

$(BUILD_DIR):
	mkdir -p $@

$(LIB): nullifier_v1.c nullifier_v2.c coin_commitment_v2.c $(INCLUDE_DIR)/psp_nullifier_v1.h $(INCLUDE_DIR)/psp_nullifier_v2.h $(INCLUDE_DIR)/psp_coin_commitment_v2.h | $(BUILD_DIR)
	$(CC) -std=c11 $(CFLAGS) $(CPPFLAGS) -fPIC -shared -I$(INCLUDE_DIR) nullifier_v1.c nullifier_v2.c coin_commitment_v2.c -lcrypto -o $@

$(TEST_BIN): nullifier_v1.c nullifier_v2.c tests/test_nullifier_v1.c $(INCLUDE_DIR)/psp_nullifier_v1.h $(INCLUDE_DIR)/psp_nullifier_v2.h | $(BUILD_DIR)
	$(CC) -std=c11 $(CFLAGS) $(CPPFLAGS) -I$(INCLUDE_DIR) nullifier_v1.c nullifier_v2.c tests/test_nullifier_v1.c -lcrypto -o $@

$(V2_TEST_BIN): nullifier_v1.c nullifier_v2.c coin_commitment_v2.c tests/test_nullifier_v2.c $(INCLUDE_DIR)/psp_nullifier_v1.h $(INCLUDE_DIR)/psp_nullifier_v2.h $(INCLUDE_DIR)/psp_coin_commitment_v2.h | $(BUILD_DIR)
	$(CC) -std=c11 $(CFLAGS) $(CPPFLAGS) -I$(INCLUDE_DIR) nullifier_v1.c nullifier_v2.c coin_commitment_v2.c tests/test_nullifier_v2.c -lcrypto -o $@

$(TIMING_BIN): nullifier_v1.c tests/timing_probe_v1.c $(INCLUDE_DIR)/psp_nullifier_v1.h | $(BUILD_DIR)
	$(CC) -std=c11 $(CFLAGS) $(CPPFLAGS) -I$(INCLUDE_DIR) nullifier_v1.c tests/timing_probe_v1.c -lcrypto -lm -o $@

timing-probe-build: $(TIMING_BIN)
	@printf 'Built preliminary V1 timing probe; not a constant-time certification.\\n'

$(TIMING_V2_BIN): nullifier_v2.c tests/timing_probe_v2.c $(INCLUDE_DIR)/psp_nullifier_v1.h $(INCLUDE_DIR)/psp_nullifier_v2.h | $(BUILD_DIR)
	$(CC) -std=c11 $(CFLAGS) $(CPPFLAGS) -I$(INCLUDE_DIR) nullifier_v2.c tests/timing_probe_v2.c -lcrypto -lm -o $@

timing-v2-probe-build: $(TIMING_V2_BIN)
	@printf 'Built V2 timing screen; it must be run on a controlled host and is not proof of constant-time execution.\\n'

timing-v2: $(TIMING_V2_BIN)
	./$(TIMING_V2_BIN)

test: $(LIB) $(TEST_BIN) $(V2_TEST_BIN)
	./$(TEST_BIN)
	./$(V2_TEST_BIN)

SANITIZE_CFLAGS := -O1 -g -Wall -Wextra -Werror -pedantic -fsanitize=address,undefined -fno-omit-frame-pointer

$(SAN_TEST_V1_BIN): nullifier_v1.c nullifier_v2.c coin_commitment_v2.c tests/test_nullifier_v1.c $(INCLUDE_DIR)/psp_nullifier_v1.h $(INCLUDE_DIR)/psp_nullifier_v2.h $(INCLUDE_DIR)/psp_coin_commitment_v2.h | $(BUILD_DIR)
	$(CC) -std=c11 $(SANITIZE_CFLAGS) $(CPPFLAGS) -I$(INCLUDE_DIR) nullifier_v1.c nullifier_v2.c coin_commitment_v2.c tests/test_nullifier_v1.c -lcrypto -o $@

$(SAN_TEST_V2_BIN): nullifier_v1.c nullifier_v2.c coin_commitment_v2.c tests/test_nullifier_v2.c $(INCLUDE_DIR)/psp_nullifier_v1.h $(INCLUDE_DIR)/psp_nullifier_v2.h $(INCLUDE_DIR)/psp_coin_commitment_v2.h | $(BUILD_DIR)
	$(CC) -std=c11 $(SANITIZE_CFLAGS) $(CPPFLAGS) -I$(INCLUDE_DIR) nullifier_v1.c nullifier_v2.c coin_commitment_v2.c tests/test_nullifier_v2.c -lcrypto -o $@

sanitize-test: $(SAN_TEST_V1_BIN) $(SAN_TEST_V2_BIN)
	ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ./$(SAN_TEST_V1_BIN)
	ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ./$(SAN_TEST_V2_BIN)

audit: $(LIB)
	$(OBJDUMP) -d -Mintel $(LIB) > $(DISASM)
	@printf 'Wrote optimized wrapper disassembly to %s\n' $(DISASM)
	@printf 'WARNING: wrapper disassembly does not inspect OpenSSL internals or prove constant-time execution.\n'

timing: $(TIMING_BIN)
	./$(TIMING_BIN)

clean:
	rm -rf $(BUILD_DIR)
