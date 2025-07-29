// Minimal test for RegDeleteKeyExA
#include <windows.h>
#include <iostream>
#include <string>

int main() {
    HKEY hKey = HKEY_CURRENT_USER;
    std::string subKeyA = "SOFTWARE\\VulnDemo\\TaintedSubkey_ExA";
    LSTATUS res = RegDeleteKeyExA(hKey, subKeyA.c_str(), KEY_WOW64_32KEY, 0);
    std::cout << "RegDeleteKeyExA: " << res << std::endl;
    return 0;
}