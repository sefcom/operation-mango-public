// Test program: Calls both RegDeleteKeyA and RegDeleteKeyW in one binary
#include <windows.h>
#include <iostream>
#include <string>

int main() {
    HKEY hKey = HKEY_CURRENT_USER;
    std::string subKeyA = "SOFTWARE\\VulnDemo\\ComboTestA";
    std::wstring subKeyW = L"SOFTWARE\\VulnDemo\\ComboTestW";

    LSTATUS resA = RegDeleteKeyA(hKey, subKeyA.c_str());
    std::cout << "RegDeleteKeyA: " << resA << std::endl;

    LSTATUS resW = RegDeleteKeyW(hKey, subKeyW.c_str());
    std::wcout << L"RegDeleteKeyW: " << resW << std::endl;

    return 0;
}