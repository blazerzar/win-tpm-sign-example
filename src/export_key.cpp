#include <iostream>

#include <windows.h>
#include <ncrypt.h>

// [ ] Clean up not implemented
#define CHECK_RESULT(result, expected, msg) \
    if (result != expected) { \
        std::cerr << msg << ": " << result << " (0x" << std::hex << result << ")\n"; \
        exit(1); \
    }

#ifdef SOFTWARE
#define PROVIDER MS_KEY_STORAGE_PROVIDER
#endif
#ifndef SOFTWARE
#define PROVIDER MS_PLATFORM_CRYPTO_PROVIDER
#endif

/* Export plaintext public key from [hKey] */
void exportPublicKey(NCRYPT_KEY_HANDLE hKey) {
    DWORD size;
    CryptExportPublicKeyInfo(
        hKey, 0, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, NULL, &size);
    auto keyInfo = (PCERT_PUBLIC_KEY_INFO) (new unsigned char[size]);
    CryptExportPublicKeyInfo(
        hKey, 0, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, keyInfo, &size);

    CryptEncodeObjectEx(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
        keyInfo, 0, NULL, NULL, &size);
    unsigned char *encoded = new unsigned char[size];
    CryptEncodeObjectEx(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
        keyInfo, 0, NULL, encoded, &size);

    DWORD binarySize = size;

    CryptBinaryToStringW(
        encoded, binarySize, CRYPT_STRING_BASE64,
        NULL, &size
    );
    WCHAR *publicKey = new WCHAR[size + 1];
    publicKey[size] = 0;
    CryptBinaryToStringW(
        encoded, binarySize, CRYPT_STRING_BASE64,
        publicKey, &size
    );

    std::cout << "-----BEGIN PUBLIC KEY-----\n";
    std::wcout << publicKey;
    std::cout << "-----END PUBLIC KEY-----\n" << std::flush;

    NCryptFreeBuffer(publicKey);
    NCryptFreeBuffer(encoded);
    NCryptFreeBuffer(keyInfo);
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

    exportPublicKey(hKey);
    NCryptFreeObject(hKey);

    return 0;
}