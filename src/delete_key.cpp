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

int main() {
    // Load and initialize a CNG key storage provider
    NCRYPT_PROV_HANDLE hProvider;
    SECURITY_STATUS status = NCryptOpenStorageProvider(
        &hProvider, PROVIDER, 0
    );
    CHECK_RESULT(status, ERROR_SUCCESS, "Failed to open storage provider");
    std::cout << "Storage provider opened successfully\n";

    // Open key
    NCRYPT_KEY_HANDLE hKey;
    status = NCryptOpenKey(hProvider, &hKey, L"Example_Key", 0, 0);
    CHECK_RESULT(status, ERROR_SUCCESS, "Failed to open key")
    std::cout << "Opened key\n";

    // Delete key
    status = NCryptDeleteKey(hKey, 0);
    if (status != ERROR_SUCCESS) {
        std::cerr << "Failed to delete key\n";
        return 1;
    }
    std::cout << "Key deleted\n";

    return 0;
}