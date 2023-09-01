#include <iostream>
#include <iomanip>

#include <stdio.h>

#include <windows.h>
#include <ncrypt.h>
#include <wincrypt.h>

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

/* List keys in [hProvider] storage provider */
void listKeys(NCRYPT_PROV_HANDLE hProvider) {
    std::cout << "Keys in storage:\n";

    NCryptKeyName *pName;
    void *enumKeysState = NULL;
    SECURITY_STATUS status = ERROR_SUCCESS;

    while (status != NTE_NO_MORE_ITEMS) {
        status = NCryptEnumKeys(
            hProvider,
            NULL,
            &pName,
            &enumKeysState,
            0
        );
        if (status == ERROR_SUCCESS) {
            std::wcout << "    - " << pName->pszName << "\n";
        }
    }

    NCryptFreeBuffer(pName);
    NCryptFreeBuffer(enumKeysState);
}

/* Create a new key with [keyName] in [hProvider] storage provider */
NCRYPT_KEY_HANDLE createKey(NCRYPT_PROV_HANDLE hProvider, LPCWSTR keyName) {
    NCRYPT_KEY_HANDLE hKey;
    SECURITY_STATUS status = NCryptCreatePersistedKey(
       hProvider, &hKey, ALGORITHM, keyName, 0, 0
    );
    CHECK_RESULT(status, ERROR_SUCCESS, "Failed to create persisted key");

    DWORD size;
    NCRYPT_SUPPORTED_LENGTHS lengths;
    status = NCryptGetProperty(
        hKey, NCRYPT_LENGTHS_PROPERTY, (PBYTE) &lengths, sizeof(lengths), &size, 0
    );
    CHECK_RESULT(status, ERROR_SUCCESS, "Failed to get property");

    std::cout << "Supported key lengths: " << lengths.dwMinLength
        << '-' << lengths.dwMaxLength << " by " << lengths.dwIncrement
        << " (" << lengths.dwDefaultLength << ")\n";

    // Set UI policy to enter key passphrase
    NCRYPT_UI_POLICY uiPolicy = {
        1, NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG,
        L"Strong key",
        L"Example key",
        L"Example of a strong asymmetric key pair"
    };
    status = NCryptSetProperty(
        hKey, NCRYPT_UI_POLICY_PROPERTY, (PBYTE) &uiPolicy, sizeof(uiPolicy), 0
    );
    CHECK_RESULT(status, ERROR_SUCCESS, "Failed to set UI policy");

    // Set parent window handle
    HWND winHandle = GetDesktopWindow();
    if (winHandle == NULL) {
        CHECK_RESULT(NTE_INVALID_HANDLE, ERROR_SUCCESS, "Failed to grab handle");
    }
    status = NCryptSetProperty(
        hKey, NCRYPT_WINDOW_HANDLE_PROPERTY, (PBYTE) &winHandle, sizeof(winHandle), 0
    );
    CHECK_RESULT(status, ERROR_SUCCESS, "Failed to set handle property");

    status = NCryptFinalizeKey(hKey, 0);
    CHECK_RESULT(status, ERROR_SUCCESS, "Failed to finalize key")

    return hKey;
}

int main() {
    // Load and initialize a CNG key storage provider
    NCRYPT_PROV_HANDLE hProvider;
    SECURITY_STATUS status = NCryptOpenStorageProvider(
        &hProvider, PROVIDER, 0
    );
    CHECK_RESULT(status, ERROR_SUCCESS, "Failed to open storage provider");
    std::cout << "Storage provider opened successfully\n";

    listKeys(hProvider);

    NCRYPT_KEY_HANDLE hKey = createKey(hProvider, L"Example_Key");
    if (hKey) {
        std::cout << "Key created\n";
    }

    listKeys(hProvider);

    NCryptFreeObject(hKey);
    NCryptFreeObject(hProvider);

    return 0;
}
