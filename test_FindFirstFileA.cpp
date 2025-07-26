#include <windows.h>
#include <stdio.h>

int main() {
    WIN32_FIND_DATAA findData;
    HANDLE hFind;
    char pattern[] = "*.*";
    char commandLine[512];

    // Source: FindFirstFileA (tainted file system metadata)
    hFind = FindFirstFileA(pattern, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("No files found.\n");
        return 1;
    }

    // For demonstration, copy the cFileName (first file found) into a command line buffer
    snprintf(commandLine, sizeof(commandLine), "notepad.exe %s", findData.cFileName);

    // Sink: CreateProcessA (uses tainted file name as command line)
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    // This is intentionally unsafe: using file system metadata as a command line
    if (!CreateProcessA(NULL, commandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("Failed to create process\n");
        FindClose(hFind);
        return 1;
    }

    printf("Process created!\n");
    FindClose(hFind);
    return 0;
}
