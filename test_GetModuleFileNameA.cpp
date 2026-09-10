#include <windows.h>
#include <stdio.h>

int main() {
    char path[MAX_PATH];

    // Source: GetModuleFileNameA (tainted input)
    GetModuleFileNameA(NULL, path, MAX_PATH);

    // Sink: CreateProcessA (uses tainted path as command line)
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    // This is intentionally unsafe: using the module file name as a command line
    if (!CreateProcessA(NULL, path, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("Failed to create process\n");
        return 1;
    }

    printf("Process created!\n");
    return 0;
}
