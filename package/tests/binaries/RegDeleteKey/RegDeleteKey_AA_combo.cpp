// Test program: Calls RegDeleteKeyA and RegDeleteKeyExA in one binary
#include <windows.h>
#include <iostream>
#include <string>

int main() {
    HKEY hKey = HKEY_CURRENT_USER;
    std::string subKeyA1 = "SOFTWARE\\VulnDemo\\ComboTestA1";
    std::string subKeyA2 = "SOFTWARE\\VulnDemo\\ComboTestA2";

    LSTATUS resA1 = RegDeleteKeyA(hKey, subKeyA1.c_str());
    std::cout << "RegDeleteKeyA: " << resA1 << std::endl;

    LSTATUS resA2 = RegDeleteKeyExA(hKey, subKeyA2.c_str(), KEY_WOW64_32KEY, 0);
    std::cout << "RegDeleteKeyExA: " << resA2 << std::endl;

    return 0;
}