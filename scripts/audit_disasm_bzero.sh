#!/usr/bin/env bash
# Advisory only: inspect optimized wrapper disassembly for visible cleansing
# call sites. This is NOT proof that all copies are cleared or code is constant-time.
set -Eeuo pipefail

binary="${1:-native/build/libpsp_nullifier.so}"
objdump_bin="${OBJDUMP:-objdump}"

if ! command -v "$objdump_bin" >/dev/null 2>&1; then
    printf 'ERROR: objdump command not found: %s\n' "$objdump_bin" >&2
    exit 2
fi
if [[ ! -f "$binary" ]]; then
    printf 'ERROR: binary not found: %s\nBuild and audit the native wrapper first.\n' "$binary" >&2
    exit 2
fi

disasm="$(mktemp)"
trap 'rm -f "$disasm"' EXIT
"$objdump_bin" -d -Mintel "$binary" > "$disasm"

extract_function() {
    local symbol="$1"
    awk -v symbol="$symbol" '
        /^[[:space:]]*[[:xdigit:]]+[[:space:]]+<[^>]+>:/ {
            if (inside) exit
            if (index($0, "<" symbol ">:") > 0) inside = 1
        }
        inside { print }
    ' "$disasm"
}

# These entry points currently contain explicit psp_secure_zero / cleansing calls.
# If source/compiler/linker changes alter this shape, investigate manually rather
# than treating this script's output as a universal zeroization guarantee.
symbols=(
    psp_nullifier_v2
    psp_nullifier_v2_generate_secret
    psp_coin_id_v2_generate
    psp_coin_commitment_v2
    psp_coin_commitment_v2_generate_salt
)
failures=0
for symbol in "${symbols[@]}"; do
    body="$(extract_function "$symbol")"
    if [[ -z "$body" ]]; then
        printf 'WARN: function symbol not found in disassembly: %s\n' "$symbol" >&2
        failures=$((failures + 1))
        continue
    fi
    if grep -Eiq 'psp_secure_zero|OPENSSL_cleanse|explicit_bzero|memset_explicit|memset_s' <<<"$body"; then
        hits="$(grep -Eio 'psp_secure_zero|OPENSSL_cleanse|explicit_bzero|memset_explicit|memset_s' <<<"$body" | sort -u | paste -sd ',' -)"
        printf 'OBSERVED: %s references %s\n' "$symbol" "$hits"
    else
        printf 'WARN: no recognized cleansing symbol visible in %s\n' "$symbol" >&2
        failures=$((failures + 1))
    fi
done

cat <<'NOTICE'
LIMITATION: visible call sites do not prove all secret copies are erased.
This script does not inspect OpenSSL provider internals, compiler runtime,
Python/ctypes copies, allocators, registers, swap/core dumps, or a ZK prover.
Treat warnings as review triggers. Do not use this diagnostic as a production
constant-time or zeroization certificate.
NOTICE

if (( failures > 0 )); then
    printf 'RESULT: manual review required (%d unresolved function(s)).\n' "$failures" >&2
    exit 1
fi
printf 'RESULT: expected wrapper cleansing references are visible; manual review remains mandatory.\n'
