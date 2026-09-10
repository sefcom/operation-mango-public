// Minimal test for RegDeleteKeyW
#include <windows.h>
#include <iostream>
#include <string>

int main() {
    HKEY hKey = HKEY_CURRENT_USER;
    std::wstring subKeyW = L"SOFTWARE\\VulnDemo\\TaintedSubkey_W";
    LSTATUS res = RegDeleteKeyW(hKey, subKeyW.c_str());
    std::wcout << L"RegDeleteKeyW: " << res << std::endl;
    return 0;
}