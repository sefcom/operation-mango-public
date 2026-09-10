#include <windows.h>
#include <iostream>

int main() {
    HKEY hKey;
    // Open a registry key (for demonstration, use HKCU\Software)
    if (RegOpenKeyA(HKEY_CURRENT_USER, "Software", &hKey) != ERROR_SUCCESS) {
        std::cerr << "Failed to open registry key\n";
        return 1;
    }

    char data[256] = {0};
    DWORD dataSize = sizeof(data);
    DWORD type = 0;
    // Read the value of the key using RegQueryValueExA
    if (RegQueryValueExA(hKey, NULL, NULL, &type, (LPBYTE)data, &dataSize) != ERROR_SUCCESS) {
        std::cerr << "Failed to query registry value\n";
        RegCloseKey(hKey);
        return 1;
    }

    // Use the registry value as a command line for CreateProcessA (vulnerable)
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(
            NULL,      // Application name
            data,      // Command line (TAINTED)
            NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        std::cerr << "Failed to create process\n";
        RegCloseKey(hKey);
        return 1;
    }

    // Clean up
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    RegCloseKey(hKey);
    return 0;
}
