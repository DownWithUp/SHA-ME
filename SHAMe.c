#include <Windows.h>
#include <stdio.h>

// Returns TRUE if success
BOOL SHAFile(LPCSTR lpszFile) {
    HCRYPTPROV	hProv;
    HCRYPTHASH	hHash;
    HANDLE		hFile;
    DWORD		dwBytesRead;
    BYTE		bReadFile[0x512];
    BYTE		bSHA[32]; // 32 Bytes, 256 bits

    hFile = CreateFileA(lpszFile, FILE_READ_ACCESS, 0, 0, OPEN_EXISTING, 0, 0);
    if (hFile == INVALID_HANDLE_VALUE) {
        return(FALSE);
    }
    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(hFile);
        return(FALSE);
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CloseHandle(hFile);
        CryptReleaseContext(hProv, 0);
        return(FALSE);
    }
    while (ReadFile(hFile, bReadFile, sizeof(bReadFile), &dwBytesRead, NULL)) {
        if (dwBytesRead == 0) {
            break; // End of file
        }
        CryptHashData(hHash, bReadFile, dwBytesRead, 0);
    }
    dwBytesRead = 32; // Repurpose variable
    if (CryptGetHashParam(hHash, HP_HASHVAL, bSHA, &dwBytesRead, 0)) {
        for (DWORD i = 0; i < dwBytesRead; i++){
            printf("%X", bSHA[i]);
        }
        printf("\n");
    }
    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CloseHandle(hFile);
    return(TRUE);
}

int main(int argc, char* argv[]) {
    if (SHAFile(argv[1])) {
    }
    else {
        printf("[!] Unable to hash file\n");
        return(-1);
    }
    return(0);
}
