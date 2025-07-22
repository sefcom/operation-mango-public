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
    
    "CreateProcessA": SimTypeFunction([
    SimTypePointer(SimTypeChar()),  # lpApplicationName
    SimTypePointer(SimTypeChar()),  # lpCommandLine
    # SimTypePointer(SimTypeBottom()), # lpProcessAttributes
    # SimTypePointer(SimTypeBottom()), # lpThreadAttributes
    # SimTypeInt(),                   # bInheritHandles
    # SimTypeInt(),                   # dwCreationFlags
    # SimTypePointer(SimTypeBottom()), # lpEnvironment
    # SimTypePointer(SimTypeChar()),  # lpCurrentDirectory
    # SimTypePointer(SimTypeBottom()), # lpStartupInfo
    # SimTypePointer(SimTypeBottom())  # lpProcessInformation
    ], SimTypeInt()),
    # "CreateProcessA": prototypes['CreateProcessA'],
    
    "ReadConsoleA": prototypes['ReadConsoleA'],
    "GetCommandLineA": prototypes['GetCommandLineA'],
    "CreateFileW" : prototypes['CreateFileW'],

    
}

