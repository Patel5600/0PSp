CC ?= cc
OBJDUMP ?= objdump
CFLAGS ?= -O2 -Wall -Wextra -Werror -pedantic
CPPFLAGS ?=
BUILD_DIR := build
INCLUDE_DIR := include
LIB := $(BUILD_DIR)/libpsp_nullifier.so
LIB_V3 := $(BUILD_DIR)/libpsp_native.so
TEST_BIN := $(BUILD_DIR)/test_nullifier_v1
V2_TEST_BIN := $(BUILD_DIR)/test_nullifier_v2
NAMESPACE_V3_TEST_BIN := $(BUILD_DIR)/test_namespace_v3
TIMING_BIN := $(BUILD_DIR)/timing_probe_v1
TIMING_V2_BIN := $(BUILD_DIR)/timing_probe_v2
TIMING_COMMITMENT_V2_BIN := $(BUILD_DIR)/timing_probe_commitment_v2
SAN_TEST_V1_BIN := $(BUILD_DIR)/test_nullifier_v1_sanitize
SAN_TEST_V2_BIN := $(BUILD_DIR)/test_nullifier_v2_sanitize
SAN_NAMESPACE_V3_BIN := $(BUILD_DIR)/test_namespace_v3_sanitize
DISASM := $(BUILD_DIR)/nullifier_native.disasm.txt

# Zero-Dependency C11 V3 Targets
TEST_KECCAK_KAT_BIN := $(BUILD_DIR)/test_keccak_kat
TEST_V3_BIN := $(BUILD_DIR)/test_v3_primitives
TEST_MOBILE_TIER1_BIN := $(BUILD_DIR)/test_mobile_tier1
TIMING_V3_BIN := $(BUILD_DIR)/timing_probe_v3_native

NATIVE_V3_SRCS := keccak_f1600.c random.c nullifier_v1.c namespace_v3.c nullifier_v2.c nullifier_v3.c coin_commitment_v2.c coin_commitment_v3.c merkle_tree_v3.c tier1_mobile.c

LDLIBS ?=
ifeq ($(OS),Windows_NT)
    LDLIBS += -lbcrypt
endif

SANITIZE_CFLAGS ?= -O1 -g -Wall -Wextra -Werror -pedantic -fsanitize=address,undefined -fno-omit-frame-pointer

.PHONY: all test test-v3 test-mobile audit timing timing-probe-build timing-v2 timing-v2-probe-build timing-commitment-v2 timing-commitment-v2-probe-build timing-v3 sanitize-test clean

all: $(LIB) $(LIB_V3)

$(BUILD_DIR):
	mkdir -p $@

$(LIB): nullifier_v1.c nullifier_v2.c coin_commitment_v2.c namespace_v3.c keccak_f1600.c random.c $(INCLUDE_DIR)/psp_nullifier_v1.h $(INCLUDE_DIR)/psp_nullifier_v2.h $(INCLUDE_DIR)/psp_coin_commitment_v2.h $(INCLUDE_DIR)/psp_namespace_v3.h | $(BUILD_DIR)
	$(CC) -std=c11 $(CFLAGS) $(CPPFLAGS) -fPIC -shared -I$(INCLUDE_DIR) nullifier_v1.c nullifier_v2.c coin_commitment_v2.c namespace_v3.c keccak_f1600.c random.c -o $@ $(LDLIBS)

$(LIB_V3): $(NATIVE_V3_SRCS) | $(BUILD_DIR)
	$(CC) -std=c11 $(CFLAGS) $(CPPFLAGS) -fPIC -shared -I$(INCLUDE_DIR) $(NATIVE_V3_SRCS) -o $@ $(LDLIBS)

$(TEST_KECCAK_KAT_BIN): keccak_f1600.c tests/test_keccak_kat.c $(INCLUDE_DIR)/psp_keccak.h | $(BUILD_DIR)
	$(CC) -std=c11 $(CFLAGS) $(CPPFLAGS) -I$(INCLUDE_DIR) keccak_f1600.c tests/test_keccak_kat.c -o $@ $(LDLIBS)

$(TEST_V3_BIN): $(NATIVE_V3_SRCS) tests/test_v3_primitives.c | $(BUILD_DIR)
	$(CC) -std=c11 $(CFLAGS) $(CPPFLAGS) -I$(INCLUDE_DIR) $(NATIVE_V3_SRCS) tests/test_v3_primitives.c -o $@ $(LDLIBS)

$(TEST_MOBILE_TIER1_BIN): $(NATIVE_V3_SRCS) tests/test_mobile_tier1.c | $(BUILD_DIR)
	$(CC) -std=c11 $(CFLAGS) $(CPPFLAGS) -I$(INCLUDE_DIR) $(NATIVE_V3_SRCS) tests/test_mobile_tier1.c -o $@ $(LDLIBS)

$(TEST_BIN): nullifier_v1.c nullifier_v2.c keccak_f1600.c random.c tests/test_nullifier_v1.c $(INCLUDE_DIR)/psp_nullifier_v1.h $(INCLUDE_DIR)/psp_nullifier_v2.h | $(BUILD_DIR)
	$(CC) -std=c11 $(CFLAGS) $(CPPFLAGS) -I$(INCLUDE_DIR) nullifier_v1.c nullifier_v2.c keccak_f1600.c random.c tests/test_nullifier_v1.c -o $@ $(LDLIBS)

$(V2_TEST_BIN): nullifier_v1.c nullifier_v2.c coin_commitment_v2.c keccak_f1600.c random.c tests/test_nullifier_v2.c $(INCLUDE_DIR)/psp_nullifier_v1.h $(INCLUDE_DIR)/psp_nullifier_v2.h $(INCLUDE_DIR)/psp_coin_commitment_v2.h | $(BUILD_DIR)
	$(CC) -std=c11 $(CFLAGS) $(CPPFLAGS) -I$(INCLUDE_DIR) nullifier_v1.c nullifier_v2.c coin_commitment_v2.c keccak_f1600.c random.c tests/test_nullifier_v2.c -o $@ $(LDLIBS)

$(NAMESPACE_V3_TEST_BIN): namespace_v3.c keccak_f1600.c random.c tests/test_namespace_v3.c $(INCLUDE_DIR)/psp_nullifier_v1.h $(INCLUDE_DIR)/psp_namespace_v3.h | $(BUILD_DIR)
	$(CC) -std=c11 $(CFLAGS) $(CPPFLAGS) -I$(INCLUDE_DIR) namespace_v3.c keccak_f1600.c random.c tests/test_namespace_v3.c -o $@ $(LDLIBS)

$(TIMING_BIN): nullifier_v1.c keccak_f1600.c random.c tests/timing_probe_v1.c $(INCLUDE_DIR)/psp_nullifier_v1.h | $(BUILD_DIR)
	$(CC) -std=c11 $(CFLAGS) $(CPPFLAGS) -I$(INCLUDE_DIR) nullifier_v1.c keccak_f1600.c random.c tests/timing_probe_v1.c -lm -o $@ $(LDLIBS)

$(TIMING_V2_BIN): nullifier_v2.c keccak_f1600.c random.c tests/timing_probe_v2.c $(INCLUDE_DIR)/psp_nullifier_v2.h | $(BUILD_DIR)
	$(CC) -std=c11 $(CFLAGS) $(CPPFLAGS) -I$(INCLUDE_DIR) nullifier_v2.c keccak_f1600.c random.c tests/timing_probe_v2.c -lm -o $@ $(LDLIBS)

$(TIMING_COMMITMENT_V2_BIN): coin_commitment_v2.c keccak_f1600.c random.c tests/timing_probe_commitment_v2.c $(INCLUDE_DIR)/psp_coin_commitment_v2.h | $(BUILD_DIR)
	$(CC) -std=c11 $(CFLAGS) $(CPPFLAGS) -I$(INCLUDE_DIR) coin_commitment_v2.c keccak_f1600.c random.c tests/timing_probe_commitment_v2.c -lm -o $@ $(LDLIBS)

$(TIMING_V3_BIN): keccak_f1600.c random.c nullifier_v3.c tests/timing_probe_v3_native.c | $(BUILD_DIR)
	$(CC) -std=c11 $(CFLAGS) $(CPPFLAGS) -I$(INCLUDE_DIR) keccak_f1600.c random.c nullifier_v3.c tests/timing_probe_v3_native.c -lm -o $@ $(LDLIBS)

timing-probe-build: $(TIMING_BIN)

timing-v2-probe-build: $(TIMING_V2_BIN)

timing-commitment-v2-probe-build: $(TIMING_COMMITMENT_V2_BIN)

timing: $(TIMING_BIN)
	./$(TIMING_BIN)

timing-v2: $(TIMING_V2_BIN)
	./$(TIMING_V2_BIN)

timing-commitment-v2: $(TIMING_COMMITMENT_V2_BIN)
	./$(TIMING_COMMITMENT_V2_BIN)

timing-v3: $(TIMING_V3_BIN)
	./$(TIMING_V3_BIN)

test: $(LIB) $(LIB_V3) $(TEST_BIN) $(V2_TEST_BIN) $(NAMESPACE_V3_TEST_BIN) $(TEST_KECCAK_KAT_BIN) $(TEST_V3_BIN) $(TEST_MOBILE_TIER1_BIN)
	./$(TEST_BIN)
	./$(V2_TEST_BIN)
	./$(NAMESPACE_V3_TEST_BIN)
	./$(TEST_KECCAK_KAT_BIN)
	./$(TEST_V3_BIN)
	./$(TEST_MOBILE_TIER1_BIN)

test-v3: $(TEST_KECCAK_KAT_BIN) $(TEST_V3_BIN) $(TEST_MOBILE_TIER1_BIN)
	./$(TEST_KECCAK_KAT_BIN)
	./$(TEST_V3_BIN)
	./$(TEST_MOBILE_TIER1_BIN)

test-mobile: $(TEST_MOBILE_TIER1_BIN)
	./$(TEST_MOBILE_TIER1_BIN)

$(SAN_TEST_V1_BIN): nullifier_v1.c nullifier_v2.c coin_commitment_v2.c keccak_f1600.c random.c tests/test_nullifier_v1.c $(INCLUDE_DIR)/psp_nullifier_v1.h $(INCLUDE_DIR)/psp_nullifier_v2.h $(INCLUDE_DIR)/psp_coin_commitment_v2.h | $(BUILD_DIR)
	$(CC) -std=c11 $(SANITIZE_CFLAGS) $(CPPFLAGS) -I$(INCLUDE_DIR) nullifier_v1.c nullifier_v2.c coin_commitment_v2.c keccak_f1600.c random.c tests/test_nullifier_v1.c -o $@ $(LDLIBS)

$(SAN_TEST_V2_BIN): nullifier_v1.c nullifier_v2.c coin_commitment_v2.c keccak_f1600.c random.c tests/test_nullifier_v2.c $(INCLUDE_DIR)/psp_nullifier_v1.h $(INCLUDE_DIR)/psp_nullifier_v2.h $(INCLUDE_DIR)/psp_coin_commitment_v2.h | $(BUILD_DIR)
	$(CC) -std=c11 $(SANITIZE_CFLAGS) $(CPPFLAGS) -I$(INCLUDE_DIR) nullifier_v1.c nullifier_v2.c coin_commitment_v2.c keccak_f1600.c random.c tests/test_nullifier_v2.c -o $@ $(LDLIBS)

$(SAN_NAMESPACE_V3_BIN): namespace_v3.c keccak_f1600.c random.c tests/test_namespace_v3.c $(INCLUDE_DIR)/psp_nullifier_v1.h $(INCLUDE_DIR)/psp_namespace_v3.h | $(BUILD_DIR)
	$(CC) -std=c11 $(SANITIZE_CFLAGS) $(CPPFLAGS) -I$(INCLUDE_DIR) namespace_v3.c keccak_f1600.c random.c tests/test_namespace_v3.c -o $@ $(LDLIBS)

sanitize-test: $(SAN_TEST_V1_BIN) $(SAN_TEST_V2_BIN) $(SAN_NAMESPACE_V3_BIN)
	ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ./$(SAN_TEST_V1_BIN)
	ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ./$(SAN_TEST_V2_BIN)
	ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ./$(SAN_NAMESPACE_V3_BIN)

audit: $(LIB) $(LIB_V3)
	$(OBJDUMP) -d -Mintel $(LIB) > $(DISASM)
	@printf 'Wrote optimized wrapper disassembly to %s\n' $(DISASM)

clean:
	rm -rf $(BUILD_DIR)
