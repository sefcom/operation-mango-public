// Minimal test for RegDeleteKeyTransactedA
#include <windows.h>
#include <iostream>
#include <string>

int main() {
    HKEY hKey = HKEY_CURRENT_USER;
    std::string subKeyA = "SOFTWARE\\VulnDemo\\TaintedSubkey_TransA";
    LSTATUS res = RegDeleteKeyTransactedA(hKey, subKeyA.c_str(), 0, 0, NULL, NULL);
    std::cout << "RegDeleteKeyTransactedA: " << res << std::endl;
    return 0;
}