from angr.sim_type import SimTypeFunction, SimTypeLong, SimTypePointer, SimTypeInt, SimTypeBottom, SimTypeChar, SimTypeRef, SimStruct

from angr.procedures.definitions.win32_kernel32 import prototypes


# Create our own declaration dicts for each teams areas 
winreg_decls = {
    #
    # Taken from: https://github.com/firmadyne/libnvram/blob/v1.0c/nvram.c .
    #
    "RegOpenKeyExW": SimTypeFunction(
        [
            SimTypeLong(signed=True),
            SimTypeLong(signed=True),
            SimTypeLong(signed=True),
            SimTypeLong(signed=True),
            SimTypeLong(signed=True),
        ],
        SimTypeLong(signed=True),
    ),
    "RegCloseKey": SimTypeFunction(
        [SimTypeLong(signed=True)], SimTypeLong(signed=True)
    ),

    "ReadConsoleA": SimTypeFunction(
    [
        SimTypeLong(signed=True),
        SimTypePointer(SimTypeChar(), offset=0),
        SimTypeInt(signed=False),
        SimTypePointer(SimTypeInt(), offset=0),
        SimTypeLong(signed=True),
    ], SimTypeLong(signed=True)),
    
    "CreateProcessA": SimTypeFunction([
        SimTypePointer(SimTypeChar()),      # lpApplicationName
        SimTypePointer(SimTypeChar()),      # lpCommandLine
        SimTypePointer(SimTypeBottom()),    # lpProcessAttributes
        SimTypePointer(SimTypeBottom()),    # lpThreadAttributes
        SimTypeInt(),                       # bInheritHandles
        SimTypeInt(),                       # dwCreationFlags
        SimTypePointer(SimTypeBottom()),    # lpEnvironment
        SimTypePointer(SimTypeChar()),      # lpCurrentDirectory
        SimTypePointer(SimTypeBottom()),    # lpStartupInfo
        SimTypePointer(SimTypeBottom()),    # lpProcessInformation
    ], SimTypeInt()),

    "CreateFileA": SimTypeFunction([
        SimTypePointer(SimTypeChar()),      # lpFileName
        SimTypeInt(),                       # dwDesiredAccess
        SimTypeInt(),                       # dwShareMode
        SimTypePointer(SimTypeBottom()),    # lpSecurityAttributes
        SimTypeInt(),                       # dwCreationDisposition
        SimTypeInt(),                       # dwFlagsAndAttributes
        SimTypePointer(SimTypeBottom()),    # hTemplateFile
    ], SimTypePointer(SimTypeBottom())),   # Returns HANDLE

    "GetCommandLineA": SimTypeFunction([], SimTypePointer(SimTypeChar())),
    
    # Example: GetEnvironmentVariableA from MSDN
    "GetEnvironmentVariableA": SimTypeFunction([
        SimTypePointer(SimTypeChar()),      # lpName
        SimTypePointer(SimTypeChar()),      # lpBuffer  
        SimTypeInt(),                       # nSize
    ], SimTypeInt()),                       # Return: DWORD
    
    "GetStdHandle": SimTypeFunction([
        SimTypeInt(),                      # nStdHandle (DWORD)
    ], SimTypePointer(SimTypeBottom())),# Returns HANDLE
    
    "SetEnvironmentVariableA": SimTypeFunction([
        SimTypePointer(SimTypeChar()),      # lpName
        SimTypePointer(SimTypeChar()),      # lpValue
    ], SimTypeInt()),                       # Return: BOOL (as int)

    "CloseHandle": SimTypeFunction([
        SimTypePointer(SimTypeBottom()),    # hObject (HANDLE)
    ], SimTypeInt()),                       # Returns BOOL
    "GlobalAlloc": SimTypeFunction([
        SimTypeInt(signed=False),           # uFlags - allocation flags
        SimTypeLong(signed=False),          # dwBytes - size in bytes
    ], SimTypePointer(SimTypeBottom())),   # Returns: HGLOBAL (memory handle)

    "GlobalFree": SimTypeFunction([
        SimTypePointer(SimTypeBottom()),    # hMem - memory handle to free
    ], SimTypePointer(SimTypeBottom())),   # Returns: HGLOBAL (NULL on success)
    "HeapAlloc": SimTypeFunction([
    SimTypePointer(SimTypeBottom()),       # hHeap (HANDLE)
    SimTypeInt(),                          # dwFlags (DWORD)
    SimTypeLong(signed=False),             # dwBytes (SIZE_T)
    ], SimTypePointer(SimTypeBottom())),   # Returns LPVOID

    
    "HeapFree": SimTypeFunction([
        SimTypePointer(SimTypeBottom()),    # hHeap (HANDLE)
        SimTypeInt(),                       # dwFlags (DWORD)
        SimTypePointer(SimTypeBottom()),    # lpMem (LPVOID)
    ], SimTypeInt()),                       # Returns BOOL
    "LocalAlloc": SimTypeFunction([
        SimTypeInt(signed=False),           # uFlags - allocation flags
        SimTypeLong(signed=False),          # uBytes - size in bytes
    ], SimTypePointer(SimTypeBottom())),   # Returns: HLOCAL (local memory handle)

    "LocalFree": SimTypeFunction([
        SimTypePointer(SimTypeBottom()),    # hMem - local memory handle to free
    ], SimTypePointer(SimTypeBottom())),   # Returns: HLOCAL (NULL on success)
    "lstrcatA": SimTypeFunction([
        SimTypePointer(SimTypeChar()),      # lpString1 (destination)
        SimTypePointer(SimTypeChar()),      # lpString2 (source to append)
    ], SimTypePointer(SimTypeChar())),      # Returns lpString1
    
    "lstrcpyA": SimTypeFunction([
        SimTypePointer(SimTypeChar()),      # lpString1 (destination)
        SimTypePointer(SimTypeChar()),      # lpString2 (source)
    ], SimTypePointer(SimTypeChar())),      # Returns lpString1
    
    
    "lstrlenA": SimTypeFunction([
        SimTypePointer(SimTypeChar()),      # lpString
    ], SimTypeInt()),                       # Returns int (string length)


    "VirtualAlloc": SimTypeFunction([
        SimTypePointer(SimTypeBottom()),    # lpAddress - starting address
        SimTypeLong(signed=False),          # dwSize - size of allocation
        SimTypeInt(signed=False),           # flAllocationType - allocation type
        SimTypeInt(signed=False),           # flProtect - protection flags
    ], SimTypePointer(SimTypeBottom())),   # Returns: LPVOID (allocated memory pointer)
    
    "VirtualFree": SimTypeFunction([
        SimTypePointer(SimTypeBottom()),    # lpAddress - address to free
        SimTypeLong(signed=False),          # dwSize - size to free
        SimTypeInt(signed=False),           # dwFreeType - free type flags
    ], SimTypeInt()),                       # Returns: BOOL
    
    "GetCurrentProcess": SimTypeFunction([
    ], SimTypePointer(SimTypeBottom)),
}

