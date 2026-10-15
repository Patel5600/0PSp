#if defined(__ANDROID__) || defined(ENABLE_JNI)

#include <jni.h>
#include <string.h>
#include "include/psp_mobile.h"

/* Helper macro to safely get byte array elements */
#define GET_BYTES(jarr, ptr, len) \
    do { \
        if ((jarr) == NULL) return NULL; \
        (len) = (*env)->GetArrayLength(env, (jarr)); \
        (ptr) = (const uint8_t *)(*env)->GetByteArrayElements(env, (jarr), NULL); \
    } while (0)

#define RELEASE_BYTES(jarr, ptr) \
    do { \
        if ((jarr) != NULL && (ptr) != NULL) { \
            (*env)->ReleaseByteArrayElements(env, (jarr), (jbyte *)(ptr), JNI_ABORT); \
        } \
    } while (0)

JNIEXPORT jbyteArray JNICALL Java_org_zeropsp_PspMobile_deriveNamespaceV3(
    JNIEnv *env, jclass clazz,
    jbyteArray ledgerId, jbyteArray deployId, jbyteArray assetId) {
    (void)clazz;
    const uint8_t *p_ledger = NULL, *p_deploy = NULL, *p_asset = NULL;
    jsize len_ledger = 0, len_deploy = 0, len_asset = 0;
    uint8_t out[PSP_TIER1_NAMESPACE_BYTES];
    jbyteArray result = NULL;
    int st;

    GET_BYTES(ledgerId, p_ledger, len_ledger);
    GET_BYTES(deployId, p_deploy, len_deploy);
    GET_BYTES(assetId, p_asset, len_asset);

    st = psp_namespace_v3_derive(
        p_ledger, (size_t)len_ledger,
        p_deploy, (size_t)len_deploy,
        p_asset, (size_t)len_asset,
        out, sizeof(out)
    );

    RELEASE_BYTES(ledgerId, p_ledger);
    RELEASE_BYTES(deployId, p_deploy);
    RELEASE_BYTES(assetId, p_asset);

    if (st == PSP_CRYPTO_OK) {
        result = (*env)->NewByteArray(env, sizeof(out));
        if (result != NULL) {
            (*env)->SetByteArrayRegion(env, result, 0, sizeof(out), (const jbyte *)out);
        }
    }
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_zeropsp_PspMobile_commitCoinV3(
    JNIEnv *env, jclass clazz,
    jbyteArray paramsId, jbyteArray pkBundle, jlong value,
    jbyteArray namespaceId, jbyteArray coinId, jbyteArray rNf, jbyteArray rhoCoin) {
    (void)clazz;
    const uint8_t *p_params = NULL, *p_bundle = NULL, *p_ns = NULL;
    const uint8_t *p_coin = NULL, *p_rnf = NULL, *p_rho = NULL;
    jsize len_params = 0, len_bundle = 0, len_ns = 0;
    jsize len_coin = 0, len_rnf = 0, len_rho = 0;
    uint8_t out[PSP_TIER1_COMMITMENT_BYTES];
    jbyteArray result = NULL;
    int st;

    GET_BYTES(paramsId, p_params, len_params);
    GET_BYTES(pkBundle, p_bundle, len_bundle);
    GET_BYTES(namespaceId, p_ns, len_ns);
    GET_BYTES(coinId, p_coin, len_coin);
    GET_BYTES(rNf, p_rnf, len_rnf);
    GET_BYTES(rhoCoin, p_rho, len_rho);

    st = psp_coin_commitment_v3(
        p_params, (size_t)len_params,
        p_bundle, (size_t)len_bundle,
        (uint64_t)value,
        p_ns, (size_t)len_ns,
        p_coin, (size_t)len_coin,
        p_rnf, (size_t)len_rnf,
        p_rho, (size_t)len_rho,
        out, sizeof(out)
    );

    RELEASE_BYTES(paramsId, p_params);
    RELEASE_BYTES(pkBundle, p_bundle);
    RELEASE_BYTES(namespaceId, p_ns);
    RELEASE_BYTES(coinId, p_coin);
    RELEASE_BYTES(rNf, p_rnf);
    RELEASE_BYTES(rhoCoin, p_rho);

    if (st == PSP_CRYPTO_OK) {
        result = (*env)->NewByteArray(env, sizeof(out));
        if (result != NULL) {
            (*env)->SetByteArrayRegion(env, result, 0, sizeof(out), (const jbyte *)out);
        }
    }
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_zeropsp_PspMobile_deriveNullifierV3(
    JNIEnv *env, jclass clazz,
    jbyteArray nk, jbyteArray namespaceId, jbyteArray paramsId,
    jbyteArray pkBundle, jbyteArray commitment, jbyteArray coinId, jbyteArray rNf) {
    (void)clazz;
    const uint8_t *p_nk = NULL, *p_ns = NULL, *p_params = NULL;
    const uint8_t *p_bundle = NULL, *p_commit = NULL, *p_coin = NULL, *p_rnf = NULL;
    jsize len_nk = 0, len_ns = 0, len_params = 0;
    jsize len_bundle = 0, len_commit = 0, len_coin = 0, len_rnf = 0;
    uint8_t out[PSP_TIER1_NULLIFIER_BYTES];
    jbyteArray result = NULL;
    int st;

    GET_BYTES(nk, p_nk, len_nk);
    GET_BYTES(namespaceId, p_ns, len_ns);
    GET_BYTES(paramsId, p_params, len_params);
    GET_BYTES(pkBundle, p_bundle, len_bundle);
    GET_BYTES(commitment, p_commit, len_commit);
    GET_BYTES(coinId, p_coin, len_coin);
    GET_BYTES(rNf, p_rnf, len_rnf);

    st = psp_nullifier_v3(
        p_nk, (size_t)len_nk,
        p_ns, (size_t)len_ns,
        p_params, (size_t)len_params,
        p_bundle, (size_t)len_bundle,
        p_commit, (size_t)len_commit,
        p_coin, (size_t)len_coin,
        p_rnf, (size_t)len_rnf,
        out, sizeof(out)
    );

    RELEASE_BYTES(nk, p_nk);
    RELEASE_BYTES(namespaceId, p_ns);
    RELEASE_BYTES(paramsId, p_params);
    RELEASE_BYTES(pkBundle, p_bundle);
    RELEASE_BYTES(commitment, p_commit);
    RELEASE_BYTES(coinId, p_coin);
    RELEASE_BYTES(rNf, p_rnf);

    if (st == PSP_CRYPTO_OK) {
        result = (*env)->NewByteArray(env, sizeof(out));
        if (result != NULL) {
            (*env)->SetByteArrayRegion(env, result, 0, sizeof(out), (const jbyte *)out);
        }
    }
    return result;
}

JNIEXPORT jboolean JNICALL Java_org_zeropsp_PspMobile_verifyMerklePath(
    JNIEnv *env, jclass clazz,
    jbyteArray namespaceId, jlong leafIndex, jbyteArray commitment,
    jbyteArray siblingsFlat, jint depth, jbyteArray expectedRoot) {
    (void)clazz;
    const uint8_t *p_ns = NULL, *p_commit = NULL, *p_siblings = NULL, *p_root = NULL;
    jsize len_ns = 0, len_commit = 0, len_siblings = 0, len_root = 0;
    int st;

    GET_BYTES(namespaceId, p_ns, len_ns);
    GET_BYTES(commitment, p_commit, len_commit);
    GET_BYTES(siblingsFlat, p_siblings, len_siblings);
    GET_BYTES(expectedRoot, p_root, len_root);

    if (len_siblings != depth * (jsize)PSP_MERKLE_NODE_BYTES) {
        RELEASE_BYTES(namespaceId, p_ns);
        RELEASE_BYTES(commitment, p_commit);
        RELEASE_BYTES(siblingsFlat, p_siblings);
        RELEASE_BYTES(expectedRoot, p_root);
        return JNI_FALSE;
    }

    st = psp_merkle_verify_path(
        p_ns, (uint64_t)leafIndex, p_commit,
        p_siblings, (size_t)depth, p_root
    );

    RELEASE_BYTES(namespaceId, p_ns);
    RELEASE_BYTES(commitment, p_commit);
    RELEASE_BYTES(siblingsFlat, p_siblings);
    RELEASE_BYTES(expectedRoot, p_root);

    return (st == PSP_CRYPTO_OK) ? JNI_TRUE : JNI_FALSE;
}

#endif /* __ANDROID__ || ENABLE_JNI */
