// language: C++, file: src/crypto.h
#pragma once
#include <windows.h>
#include <bcrypt.h>
#include <cstdint>
#include <vector>
#pragma comment(lib, "bcrypt.lib")

inline bool aes_cbc_decrypt(const uint8_t* key, const uint8_t* iv,
                            const uint8_t* in, size_t in_len, std::vector<uint8_t>& out) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE kh  = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) return false;
    if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                          sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0); return false;
    }
    if (BCryptGenerateSymmetricKey(alg, &kh, nullptr, 0, (PUCHAR)key, 32, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0); return false;
    }
    BCryptSetProperty(kh, BCRYPT_INITIALIZATION_VECTOR, (PUCHAR)iv, 16, 0);
    ULONG out_len = 0;
    if (BCryptDecrypt(kh, (PUCHAR)in, (ULONG)in_len, nullptr, nullptr, 0,
                      out.data(), (ULONG)out.size(), &out_len, 0) != 0) {
        BCryptDestroyKey(kh); BCryptCloseAlgorithmProvider(alg, 0); return false;
    }
    out.resize(out_len);
    BCryptDestroyKey(kh);
    BCryptCloseAlgorithmProvider(alg, 0);
    return true;
}

inline void wipe(void* p, size_t n) {
    SecureZeroMemory(p, n);
}
