#include <iostream>

#include <stdio.h>

#include <windows.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <ntstatus.h>

// [ ] Clean up not implemented
#define CHECK_RESULT(result, expected, msg) \
    if (result != expected) { \
        std::cerr << msg << ": " << result << " (0x" << std::hex << result << ")\n"; \
        exit(1); \
    }

#ifdef ELLIPTIC
#define ALGORITHM BCRYPT_ECDSA_P384_ALGORITHM
#endif
#ifndef ELLIPTIC
#define ALGORITHM BCRYPT_RSA_ALGORITHM
#endif

#ifdef SOFTWARE
#define PROVIDER MS_KEY_STORAGE_PROVIDER
#endif
#ifndef SOFTWARE
#define PROVIDER MS_PLATFORM_CRYPTO_PROVIDER
#endif

unsigned char *createHash() {
    BCRYPT_ALG_HANDLE hAlgorithm;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &hAlgorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0
    );
    CHECK_RESULT(status, STATUS_SUCCESS, "Cannot open algorithm provider");

    DWORD size, result;
    status = BCryptGetProperty(
        hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE) &size,
        sizeof(DWORD), &result, 0
    );
    CHECK_RESULT(status, STATUS_SUCCESS, "Cannot get hash object length");

    BCRYPT_HASH_HANDLE hHash;
    status = BCryptCreateHash(hAlgorithm, &hHash, NULL, 0, NULL, 0, 0);
    CHECK_RESULT(status, STATUS_SUCCESS, "Cannot create hash object");

    const char *input = "Secret challenge";
    status = BCryptHashData(hHash, (PUCHAR) input, strlen(input), 0);
    CHECK_RESULT(status, STATUS_SUCCESS, "Cannot add data to hash");

    status = BCryptGetProperty(
        hAlgorithm, BCRYPT_HASH_LENGTH, (PBYTE) &size,
        sizeof(DWORD), &result, 0
    );
    CHECK_RESULT(status, STATUS_SUCCESS, "Cannot get hash length");

    unsigned char *hash = new unsigned char[size];
    status = BCryptFinishHash(hHash, hash, size, 0);
    CHECK_RESULT(status, STATUS_SUCCESS, "Hashing failed");

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);

    return hash;
}

unsigned char *signHash(NCRYPT_KEY_HANDLE hKey, unsigned char *hash, DWORD *size) {
    #ifndef ELLIPTIC
    BCRYPT_PKCS1_PADDING_INFO padding = {
        BCRYPT_SHA256_ALGORITHM
    };
    #endif

    SECURITY_STATUS status = NCryptSignHash(
        #ifndef ELLIPTIC
        hKey, &padding, hash, 32, NULL, 0, size, BCRYPT_PAD_PKCS1
        #endif
        #ifdef ELLIPTIC
        hKey, NULL, hash, 32, NULL, 0, size, 0
        #endif
    );
    CHECK_RESULT(status, ERROR_SUCCESS, "Signing failed");

    unsigned char *signature = new unsigned char[*size];
    status = NCryptSignHash(
        #ifndef ELLIPTIC
        hKey, &padding, hash, 32, signature, *size, size, BCRYPT_PAD_PKCS1
        #endif
        #ifdef ELLIPTIC
        hKey, NULL, hash, 32, signature, *size, size, 0
        #endif
    );
    CHECK_RESULT(status, ERROR_SUCCESS, "Signing failed");

    return signature;
}

int main() {
    // Load and initialize a CNG key storage provider
    NCRYPT_PROV_HANDLE hProvider;
    SECURITY_STATUS status = NCryptOpenStorageProvider(
        &hProvider, PROVIDER, 0
    );
    CHECK_RESULT(status, ERROR_SUCCESS, "Failed to open storage provider");

    // Open key
    NCRYPT_KEY_HANDLE hKey;
    status = NCryptOpenKey(hProvider, &hKey, L"Example_Key", 0, 0);
    CHECK_RESULT(status, ERROR_SUCCESS, "Failed to open key")

    // Create hash and sign it using private key
    unsigned char *hash = createHash();
    DWORD size;
    unsigned char *signature = signHash(hKey, hash, &size);

    for (decltype(size) i = 0; i < size; ++i) {
        printf("%02x", signature[i]);
    }
    std::cout << '\n';

    // Make sure signature is valid
    #ifndef ELLIPTIC
    BCRYPT_PKCS1_PADDING_INFO padding = {
        BCRYPT_SHA256_ALGORITHM
    };
    #endif

    status = NCryptVerifySignature(
        #ifndef ELLIPTIC
        hKey, &padding, hash, 32, signature, size, BCRYPT_PAD_PKCS1
        #endif
        #ifdef ELLIPTIC
        hKey, NULL, hash, 32, signature, size, 0
        #endif
    );
    CHECK_RESULT(status, ERROR_SUCCESS, "Signature verification failed");

    NCryptFreeObject(hKey);
    delete hash;
    delete signature;

    return 0;
}