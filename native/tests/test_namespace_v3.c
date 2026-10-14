#include "psp_namespace_v3.h"
#include "psp_keccak.h"

#include <stdio.h>
#include <string.h>

static const uint8_t DOMAIN_LEDGER[] = "0PSP-EVM-LEDGER-IDENTITY-v1";
static const uint8_t DOMAIN_DEPLOYMENT[] = "0PSP-EVM-DEPLOYMENT-IDENTITY-v1";
static const uint8_t DOMAIN_ASSET[] = "0PSP-EVM-ASSET-IDENTITY-v1";

static int equals_hex(const uint8_t *value, size_t length, const char *hex) {
    size_t i;
    if (strlen(hex) != length * 2u) return 0;
    for (i = 0u; i < length; ++i) {
        unsigned int expected;
        if (sscanf(hex + (i * 2u), "%2x", &expected) != 1 ||
            value[i] != (uint8_t)expected) {
            return 0;
        }
    }
    return 1;
}

static int all_zero(const uint8_t *value, size_t length) {
    size_t i;
    for (i = 0u; i < length; ++i) {
        if (value[i] != 0u) return 0;
    }
    return 1;
}

static size_t build_evm_descriptors(
    uint8_t *ledger, size_t ledger_capacity,
    uint8_t *deployment, size_t deployment_capacity,
    uint8_t *asset, size_t asset_capacity,
    uint8_t deployment_epoch, uint8_t asset_epoch) {
    uint8_t chain_id[32] = {0u};
    uint8_t genesis_hash[32];
    uint8_t protocol_address[20];
    uint8_t asset_address[20];
    size_t offset;
    if (ledger_capacity != sizeof(DOMAIN_LEDGER) - 1u + 1u + 32u + 32u ||
        deployment_capacity != sizeof(DOMAIN_DEPLOYMENT) - 1u + 1u + 20u + 8u ||
        asset_capacity != sizeof(DOMAIN_ASSET) - 1u + 1u + 1u + 20u + 8u) {
        return 0u;
    }

    chain_id[31] = 1u;
    memset(genesis_hash, 0x01, sizeof(genesis_hash));
    memset(protocol_address, 0x11, sizeof(protocol_address));
    memset(asset_address, 0x22, sizeof(asset_address));

    offset = 0u;
    memcpy(ledger + offset, DOMAIN_LEDGER, sizeof(DOMAIN_LEDGER) - 1u);
    offset += sizeof(DOMAIN_LEDGER) - 1u;
    ledger[offset++] = 1u;
    memcpy(ledger + offset, chain_id, sizeof(chain_id));
    offset += sizeof(chain_id);
    memcpy(ledger + offset, genesis_hash, sizeof(genesis_hash));
    offset += sizeof(genesis_hash);

    offset = 0u;
    memcpy(deployment + offset, DOMAIN_DEPLOYMENT, sizeof(DOMAIN_DEPLOYMENT) - 1u);
    offset += sizeof(DOMAIN_DEPLOYMENT) - 1u;
    deployment[offset++] = 1u;
    memcpy(deployment + offset, protocol_address, sizeof(protocol_address));
    offset += sizeof(protocol_address);
    memset(deployment + offset, 0, 8u);
    deployment[offset + 7u] = deployment_epoch;

    offset = 0u;
    memcpy(asset + offset, DOMAIN_ASSET, sizeof(DOMAIN_ASSET) - 1u);
    offset += sizeof(DOMAIN_ASSET) - 1u;
    asset[offset++] = 1u;
    asset[offset++] = 1u; /* token-asset type */
    memcpy(asset + offset, asset_address, sizeof(asset_address));
    offset += sizeof(asset_address);
    memset(asset + offset, 0, 8u);
    asset[offset + 7u] = asset_epoch;

    psp_secure_zero(chain_id, sizeof(chain_id));
    psp_secure_zero(genesis_hash, sizeof(genesis_hash));
    psp_secure_zero(protocol_address, sizeof(protocol_address));
    psp_secure_zero(asset_address, sizeof(asset_address));
    return 1u;
}

int main(void) {
    uint8_t ledger[sizeof(DOMAIN_LEDGER) - 1u + 1u + 32u + 32u];
    uint8_t deployment[sizeof(DOMAIN_DEPLOYMENT) - 1u + 1u + 20u + 8u];
    uint8_t asset[sizeof(DOMAIN_ASSET) - 1u + 1u + 1u + 20u + 8u];
    uint8_t out[PSP_NAMESPACE_V3_ID_BYTES];
    uint8_t changed[PSP_NAMESPACE_V3_ID_BYTES];
    static const char expected[] =
        "d77ec0ca141c09b8249453a0aaded14b"
        "9fd3aefe2b90c8aafc1cf568d016bd56"
        "d063c3fe16f9a766663e686e9d298413";
    if (build_evm_descriptors(
            ledger, sizeof(ledger), deployment, sizeof(deployment),
            asset, sizeof(asset), 0u, 0u) != 1u) {
        fputs("FAIL: descriptor fixture size\\n", stderr);
        return 1;
    }

    if (psp_namespace_v3_derive(
            ledger, sizeof(ledger), deployment, sizeof(deployment),
            asset, sizeof(asset), out, sizeof(out)) != PSP_NULLIFIER_OK ||
        !equals_hex(out, sizeof(out), expected)) {
        fputs("FAIL: Namespace V3 EVM known-answer vector\\n", stderr);
        return 1;
    }

    if (psp_namespace_v3_derive(
            ledger, sizeof(ledger), deployment, sizeof(deployment),
            asset, sizeof(asset), changed, sizeof(changed)) != PSP_NULLIFIER_OK ||
        memcmp(out, changed, sizeof(out)) != 0) {
        fputs("FAIL: Namespace V3 deterministic derivation\\n", stderr);
        return 1;
    }

    deployment[sizeof(deployment) - 1u] = 1u;
    if (psp_namespace_v3_derive(
            ledger, sizeof(ledger), deployment, sizeof(deployment),
            asset, sizeof(asset), changed, sizeof(changed)) != PSP_NULLIFIER_OK ||
        memcmp(out, changed, sizeof(out)) == 0) {
        fputs("FAIL: Namespace V3 deployment separation\\n", stderr);
        return 1;
    }

    memset(changed, 0xa5, sizeof(changed));
    if (psp_namespace_v3_derive(
            ledger, 0u, deployment, sizeof(deployment),
            asset, sizeof(asset), changed, sizeof(changed)) != PSP_NULLIFIER_ERR_ARGUMENT ||
        !all_zero(changed, sizeof(changed))) {
        fputs("FAIL: Namespace V3 empty input / output clearing\\n", stderr);
        return 1;
    }

    memset(changed, 0xa5, sizeof(changed));
    if (psp_namespace_v3_derive(
            ledger, PSP_NAMESPACE_V3_COMPONENT_MAX_BYTES + 1u,
            deployment, sizeof(deployment), asset, sizeof(asset),
            changed, sizeof(changed)) != PSP_NULLIFIER_ERR_ARGUMENT ||
        !all_zero(changed, sizeof(changed))) {
        fputs("FAIL: Namespace V3 oversized input / output clearing\\n", stderr);
        return 1;
    }

    psp_secure_zero(out, sizeof(out));
    psp_secure_zero(changed, sizeof(changed));
    puts("PASS: Namespace V3 direct SHAKE256-384 vector, deterministic mapping, deployment separation and fail-closed bounds");
    puts("LIMIT: this proves implementation behavior for test vectors, not hash injectivity or RPC consensus");
    return 0;
}
