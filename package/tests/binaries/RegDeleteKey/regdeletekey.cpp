// Vulnerable C++ test program for RegDelete* Win32 APIs
// Compile with: cl /EHsc test_regdelete_vuln.cpp /link Advapi32.lib

#include <windows.h>
#include <iostream>
#include <string>

// Simulate a "source" of tainted data
std::string getTaintedRegistrySubkey() {
    return "SOFTWARE\\VulnDemo\\TaintedSubkey";
}

std::wstring getTaintedRegistrySubkeyW() {
    return L"SOFTWARE\\VulnDemo\\TaintedSubkeyW";
}

std::string getTaintedValueName() {
    return "TaintedValueA";
}

std::wstring getTaintedValueNameW() {
    return L"TaintedValueW";
}

// Simulate business logic that "forwards" taint
std::string businessLogicA(const std::string& s) { return s + "_A"; }
std::wstring businessLogicW(const std::wstring& s) { return s + L"_W"; }

int main() {
    HKEY hKey = HKEY_CURRENT_USER;

    // Source: tainted subkey/value names
    std::string subKeyA = businessLogicA(getTaintedRegistrySubkey());
    std::wstring subKeyW = businessLogicW(getTaintedRegistrySubkeyW());
    std::string valueNameA = businessLogicA(getTaintedValueName());
    std::wstring valueNameW = businessLogicW(getTaintedValueNameW());

    // Sinks: all RegDelete* APIs
   LSTATUS res1 = RegDeleteKeyA(hKey, subKeyA.c_str());
   std::cout << "RegDeleteKeyA: " << res1 << std::endl;

   LSTATUS res2 = RegDeleteKeyW(hKey, subKeyW.c_str());
    std::wcout << L"RegDeleteKeyW: " << res2 << std::endl;

    LSTATUS res3 = RegDeleteKeyExA(hKey, subKeyA.c_str(), KEY_WOW64_32KEY, 0);
    std::cout << "RegDeleteKeyExA: " << res3 << std::endl;

   LSTATUS res4 = RegDeleteKeyExW(hKey, subKeyW.c_str(), KEY_WOW64_64KEY, 0);
   std::wcout << L"RegDeleteKeyExW: " << res4 << std::endl;

   LSTATUS res5 = RegDeleteKeyTransactedA(hKey, subKeyA.c_str(), 0, 0, NULL, NULL);
   std::cout << "RegDeleteKeyTransactedA: " << res5 << std::endl;

   LSTATUS res6 = RegDeleteKeyTransactedW(hKey, subKeyW.c_str(), 0, 0, NULL, NULL);
   std::wcout << L"RegDeleteKeyTransactedW: " << res6 << std::endl;

   LSTATUS res7 = RegDeleteKeyValueA(hKey, subKeyA.c_str(), valueNameA.c_str());
   std::cout << "RegDeleteKeyValueA: " << res7 << std::endl;

   LSTATUS res8 = RegDeleteKeyValueW(hKey, subKeyW.c_str(), valueNameW.c_str());
   std::wcout << L"RegDeleteKeyValueW: " << res8 << std::endl;

    return 0;
}
