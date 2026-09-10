// Minimal test for RegDeleteKeyExW
#include <windows.h>
#include <iostream>
#include <string>

int main() {
    HKEY hKey = HKEY_CURRENT_USER;
    std::wstring subKeyW = L"SOFTWARE\\VulnDemo\\TaintedSubkey_ExW";
    LSTATUS res = RegDeleteKeyExW(hKey, subKeyW.c_str(), KEY_WOW64_64KEY, 0);
    std::wcout << L"RegDeleteKeyExW: " << res << std::endl;
    return 0;
}