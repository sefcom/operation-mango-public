// Minimal test for RegDeleteKeyValueW
#include <windows.h>
#include <iostream>
#include <string>

int main() {
    HKEY hKey = HKEY_CURRENT_USER;
    std::wstring subKeyW = L"SOFTWARE\\VulnDemo\\TaintedSubkey_ValueW";
    std::wstring valueNameW = L"TaintedValueW";
    LSTATUS res = RegDeleteKeyValueW(hKey, subKeyW.c_str(), valueNameW.c_str());
    std::wcout << L"RegDeleteKeyValueW: " << res << std::endl;
    return 0;
}