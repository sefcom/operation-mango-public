// Minimal test for RegDeleteKeyA
#include <windows.h>
#include <iostream>
#include <string>

int main() {
    HKEY hKey = HKEY_CURRENT_USER;
    std::string subKeyA = "SOFTWARE\\VulnDemo\\TaintedSubkey_A";
    LSTATUS res = RegDeleteKeyA(hKey, subKeyA.c_str());
    std::cout << "RegDeleteKeyA: " << res << std::endl;
    return 0;
}