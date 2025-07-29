// Test program: Calls two RegDeleteKeyW in one binary
#include <windows.h>
#include <iostream>
#include <string>

int main() {
    HKEY hKey = HKEY_CURRENT_USER;
    std::wstring subKeyW1 = L"SOFTWARE\\VulnDemo\\ComboTestW1";
    std::wstring subKeyW2 = L"SOFTWARE\\VulnDemo\\ComboTestW2";

    LSTATUS resW1 = RegDeleteKeyW(hKey, subKeyW1.c_str());
    std::wcout << L"RegDeleteKeyW1: " << resW1 << std::endl;

    LSTATUS resW2 = RegDeleteKeyW(hKey, subKeyW2.c_str());
    std::wcout << L"RegDeleteKeyW2: " << resW2 << std::endl;

    return 0;
}