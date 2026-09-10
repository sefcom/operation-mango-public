// Minimal test for RegDeleteKeyValueA
#include <windows.h>
#include <iostream>
#include <string>

int main() {
    HKEY hKey = HKEY_CURRENT_USER;
    std::string subKeyA = "SOFTWARE\\VulnDemo\\TaintedSubkey_ValueA";
    std::string valueNameA = "TaintedValueA";
    LSTATUS res = RegDeleteKeyValueA(hKey, subKeyA.c_str(), valueNameA.c_str());
    std::cout << "RegDeleteKeyValueA: " << res << std::endl;
    return 0;
}