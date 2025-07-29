// Minimal test for RegDeleteKeyTransactedW
#include <windows.h>
#include <iostream>
#include <string>

int main() {
    HKEY hKey = HKEY_CURRENT_USER;
    std::wstring subKeyW = L"SOFTWARE\\VulnDemo\\TaintedSubkey_TransW";
    LSTATUS res = RegDeleteKeyTransactedW(hKey, subKeyW.c_str(), 0, 0, NULL, NULL);
    std::wcout << L"RegDeleteKeyTransactedW: " << res << std::endl;
    return 0;
}