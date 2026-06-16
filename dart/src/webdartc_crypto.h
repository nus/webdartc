// Thin passthrough wrappers over BoringSSL's libcrypto for the Linux +
// Android crypto backend.
//
// BoringSSL has no stable shared-library ABI and vcpkg builds it static with
// hidden visibility, so its `EVP_*` / `EC_*` symbols cannot be bundled and
// bound directly. Instead `dart/hook/build.dart` statically links
// `libcrypto.a` into the `webdartc_crypto` shared library and exports ONLY the
// `wd_*` wrappers below (everything else stays hidden) — the same pattern as
// the libvpx / libopus codec wrappers. `dart/lib/crypto/openssl.dart` binds
// these `wd_*` symbols via `@Native`.
//
// Signatures mirror exactly what openssl.dart expects: opaque OpenSSL handles
// are `void*`, byte buffers `uint8_t*`, lengths `int`/`size_t`. The bodies in
// webdartc_crypto.c cast to the real BoringSSL types.
#ifndef WEBDARTC_CRYPTO_H_
#define WEBDARTC_CRYPTO_H_

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#define WD_EXPORT __declspec(dllexport)
#else
#define WD_EXPORT __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

// EVP_CIPHER_CTX
WD_EXPORT void* wd_EVP_CIPHER_CTX_new(void);
WD_EXPORT void wd_EVP_CIPHER_CTX_free(void* ctx);
WD_EXPORT int wd_EVP_CIPHER_CTX_ctrl(void* ctx, int type, int arg, void* ptr);

// EVP_Encrypt
WD_EXPORT int wd_EVP_EncryptInit_ex(void* ctx, const void* cipher, void* impl,
                                    const uint8_t* key, const uint8_t* iv);
WD_EXPORT int wd_EVP_EncryptUpdate(void* ctx, uint8_t* out, int* outl,
                                   const uint8_t* in, int inl);
WD_EXPORT int wd_EVP_EncryptFinal_ex(void* ctx, uint8_t* out, int* outl);

// EVP_Decrypt
WD_EXPORT int wd_EVP_DecryptInit_ex(void* ctx, const void* cipher, void* impl,
                                    const uint8_t* key, const uint8_t* iv);
WD_EXPORT int wd_EVP_DecryptUpdate(void* ctx, uint8_t* out, int* outl,
                                   const uint8_t* in, int inl);
WD_EXPORT int wd_EVP_DecryptFinal_ex(void* ctx, uint8_t* out, int* outl);

// EVP_CIPHER getters (return const EVP_CIPHER*)
WD_EXPORT void* wd_EVP_aes_128_ecb(void);
WD_EXPORT void* wd_EVP_aes_256_ecb(void);
WD_EXPORT void* wd_EVP_aes_128_gcm(void);
WD_EXPORT void* wd_EVP_aes_256_gcm(void);

// EC_KEY
WD_EXPORT void* wd_EC_KEY_new_by_curve_name(int nid);
WD_EXPORT int wd_EC_KEY_generate_key(void* key);
WD_EXPORT void wd_EC_KEY_free(void* key);
WD_EXPORT void* wd_EC_KEY_get0_public_key(void* key);
WD_EXPORT void* wd_EC_KEY_get0_private_key(void* key);
WD_EXPORT void* wd_EC_KEY_get0_group(void* key);
WD_EXPORT int wd_EC_KEY_set_public_key(void* key, void* point);

// EC_POINT
WD_EXPORT size_t wd_EC_POINT_point2oct(void* group, void* point, int form,
                                       uint8_t* buf, size_t len, void* ctx);
// Returns (void*)1 on success, NULL on failure — openssl.dart treats the
// result as a pointer and null-checks it.
WD_EXPORT void* wd_EC_POINT_oct2point(void* group, void* point,
                                      const uint8_t* buf, size_t len, void* ctx);
WD_EXPORT void* wd_EC_POINT_new(void* group);
WD_EXPORT void wd_EC_POINT_free(void* point);

// ECDH
WD_EXPORT int wd_ECDH_compute_key(uint8_t* out, int outlen, void* pub_key,
                                  void* ecdh, void* kdf);

// ECDSA
WD_EXPORT int wd_ECDSA_sign(int type, const uint8_t* dgst, int dgstlen,
                            uint8_t* sig, unsigned int* siglen, void* eckey);
WD_EXPORT int wd_ECDSA_size(void* eckey);
WD_EXPORT int wd_ECDSA_verify(int type, const uint8_t* dgst, int dgstlen,
                              const uint8_t* sig, int siglen, void* eckey);

// EVP_MD_CTX / EVP_DigestSign
WD_EXPORT void* wd_EVP_MD_CTX_new(void);
WD_EXPORT void wd_EVP_MD_CTX_free(void* ctx);
WD_EXPORT int wd_EVP_DigestSignInit(void* ctx, void** pctx, void* type,
                                    void* impl, void* pkey);
WD_EXPORT int wd_EVP_DigestSign(void* ctx, uint8_t* sig, size_t* siglen,
                                const uint8_t* tbs, size_t tbslen);

// EVP_PKEY
WD_EXPORT void* wd_EVP_PKEY_new(void);
WD_EXPORT void wd_EVP_PKEY_free(void* pkey);
WD_EXPORT int wd_EVP_PKEY_set1_EC_KEY(void* pkey, void* key);
WD_EXPORT void* wd_EVP_PKEY_get1_EC_KEY(void* pkey);

WD_EXPORT void* wd_EVP_sha256(void);

#ifdef __cplusplus
}
#endif

#endif  // WEBDARTC_CRYPTO_H_
