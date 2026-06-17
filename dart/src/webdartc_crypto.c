// Passthrough wrappers over BoringSSL libcrypto. See webdartc_crypto.h.
#include "webdartc_crypto.h"

#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

// ── EVP_CIPHER_CTX ──────────────────────────────────────────────────────────
void* wd_EVP_CIPHER_CTX_new(void) { return EVP_CIPHER_CTX_new(); }
void wd_EVP_CIPHER_CTX_free(void* ctx) {
  EVP_CIPHER_CTX_free((EVP_CIPHER_CTX*)ctx);
}
int wd_EVP_CIPHER_CTX_ctrl(void* ctx, int type, int arg, void* ptr) {
  return EVP_CIPHER_CTX_ctrl((EVP_CIPHER_CTX*)ctx, type, arg, ptr);
}

// ── EVP_Encrypt / EVP_Decrypt ───────────────────────────────────────────────
int wd_EVP_EncryptInit_ex(void* ctx, const void* cipher, void* impl,
                          const uint8_t* key, const uint8_t* iv) {
  return EVP_EncryptInit_ex((EVP_CIPHER_CTX*)ctx, (const EVP_CIPHER*)cipher,
                            (ENGINE*)impl, key, iv);
}
int wd_EVP_EncryptUpdate(void* ctx, uint8_t* out, int* outl, const uint8_t* in,
                         int inl) {
  return EVP_EncryptUpdate((EVP_CIPHER_CTX*)ctx, out, outl, in, inl);
}
int wd_EVP_EncryptFinal_ex(void* ctx, uint8_t* out, int* outl) {
  return EVP_EncryptFinal_ex((EVP_CIPHER_CTX*)ctx, out, outl);
}
int wd_EVP_DecryptInit_ex(void* ctx, const void* cipher, void* impl,
                          const uint8_t* key, const uint8_t* iv) {
  return EVP_DecryptInit_ex((EVP_CIPHER_CTX*)ctx, (const EVP_CIPHER*)cipher,
                            (ENGINE*)impl, key, iv);
}
int wd_EVP_DecryptUpdate(void* ctx, uint8_t* out, int* outl, const uint8_t* in,
                         int inl) {
  return EVP_DecryptUpdate((EVP_CIPHER_CTX*)ctx, out, outl, in, inl);
}
int wd_EVP_DecryptFinal_ex(void* ctx, uint8_t* out, int* outl) {
  return EVP_DecryptFinal_ex((EVP_CIPHER_CTX*)ctx, out, outl);
}

// ── EVP_CIPHER getters ──────────────────────────────────────────────────────
void* wd_EVP_aes_128_ecb(void) { return (void*)EVP_aes_128_ecb(); }
void* wd_EVP_aes_256_ecb(void) { return (void*)EVP_aes_256_ecb(); }
void* wd_EVP_aes_128_gcm(void) { return (void*)EVP_aes_128_gcm(); }
void* wd_EVP_aes_256_gcm(void) { return (void*)EVP_aes_256_gcm(); }

// ── EC_KEY ──────────────────────────────────────────────────────────────────
void* wd_EC_KEY_new_by_curve_name(int nid) {
  return EC_KEY_new_by_curve_name(nid);
}
int wd_EC_KEY_generate_key(void* key) {
  return EC_KEY_generate_key((EC_KEY*)key);
}
void wd_EC_KEY_free(void* key) { EC_KEY_free((EC_KEY*)key); }
void* wd_EC_KEY_get0_public_key(void* key) {
  return (void*)EC_KEY_get0_public_key((const EC_KEY*)key);
}
void* wd_EC_KEY_get0_private_key(void* key) {
  return (void*)EC_KEY_get0_private_key((const EC_KEY*)key);
}
void* wd_EC_KEY_get0_group(void* key) {
  return (void*)EC_KEY_get0_group((const EC_KEY*)key);
}
int wd_EC_KEY_set_public_key(void* key, void* point) {
  return EC_KEY_set_public_key((EC_KEY*)key, (const EC_POINT*)point);
}

// ── EC_POINT ────────────────────────────────────────────────────────────────
size_t wd_EC_POINT_point2oct(void* group, void* point, int form, uint8_t* buf,
                             size_t len, void* ctx) {
  return EC_POINT_point2oct((const EC_GROUP*)group, (const EC_POINT*)point,
                            (point_conversion_form_t)form, buf, len,
                            (BN_CTX*)ctx);
}
void* wd_EC_POINT_oct2point(void* group, void* point, const uint8_t* buf,
                            size_t len, void* ctx) {
  // Real EC_POINT_oct2point returns int (1/0); surface it as a pointer so the
  // Dart binding's null-check works (1 → non-null, 0 → null).
  int ok = EC_POINT_oct2point((const EC_GROUP*)group, (EC_POINT*)point, buf,
                              len, (BN_CTX*)ctx);
  return (void*)(intptr_t)ok;
}
void* wd_EC_POINT_new(void* group) {
  return EC_POINT_new((const EC_GROUP*)group);
}
void wd_EC_POINT_free(void* point) { EC_POINT_free((EC_POINT*)point); }

// ── ECDH ────────────────────────────────────────────────────────────────────
int wd_ECDH_compute_key(uint8_t* out, int outlen, void* pub_key, void* ecdh,
                        void* kdf) {
  return ECDH_compute_key(out, (size_t)outlen, (const EC_POINT*)pub_key,
                          (const EC_KEY*)ecdh,
                          (void* (*)(const void*, size_t, void*, size_t*))kdf);
}

// ── ECDSA ───────────────────────────────────────────────────────────────────
int wd_ECDSA_sign(int type, const uint8_t* dgst, int dgstlen, uint8_t* sig,
                  unsigned int* siglen, void* eckey) {
  return ECDSA_sign(type, dgst, dgstlen, sig, siglen, (EC_KEY*)eckey);
}
int wd_ECDSA_size(void* eckey) { return ECDSA_size((const EC_KEY*)eckey); }
int wd_ECDSA_verify(int type, const uint8_t* dgst, int dgstlen,
                    const uint8_t* sig, int siglen, void* eckey) {
  return ECDSA_verify(type, dgst, dgstlen, sig, siglen, (EC_KEY*)eckey);
}

// ── EVP_MD_CTX / EVP_DigestSign ─────────────────────────────────────────────
void* wd_EVP_MD_CTX_new(void) { return EVP_MD_CTX_new(); }
void wd_EVP_MD_CTX_free(void* ctx) { EVP_MD_CTX_free((EVP_MD_CTX*)ctx); }
int wd_EVP_DigestSignInit(void* ctx, void** pctx, void* type, void* impl,
                          void* pkey) {
  return EVP_DigestSignInit((EVP_MD_CTX*)ctx, (EVP_PKEY_CTX**)pctx,
                            (const EVP_MD*)type, (ENGINE*)impl, (EVP_PKEY*)pkey);
}
int wd_EVP_DigestSign(void* ctx, uint8_t* sig, size_t* siglen,
                      const uint8_t* tbs, size_t tbslen) {
  return EVP_DigestSign((EVP_MD_CTX*)ctx, sig, siglen, tbs, tbslen);
}

// ── EVP_PKEY ────────────────────────────────────────────────────────────────
void* wd_EVP_PKEY_new(void) { return EVP_PKEY_new(); }
void wd_EVP_PKEY_free(void* pkey) { EVP_PKEY_free((EVP_PKEY*)pkey); }
int wd_EVP_PKEY_set1_EC_KEY(void* pkey, void* key) {
  return EVP_PKEY_set1_EC_KEY((EVP_PKEY*)pkey, (EC_KEY*)key);
}
void* wd_EVP_PKEY_get1_EC_KEY(void* pkey) {
  return EVP_PKEY_get1_EC_KEY((EVP_PKEY*)pkey);
}

void* wd_EVP_sha256(void) { return (void*)EVP_sha256(); }
