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
    
    
    "HeapFree": SimTypeFunction([
        SimTypePointer(SimTypeBottom()),    # hHeap (HANDLE)
        SimTypeInt(),                       # dwFlags (DWORD)
        SimTypePointer(SimTypeBottom()),    # lpMem (LPVOID)
    ], SimTypeInt()),                       # Returns BOOL

}

