from angr.sim_type import SimTypeFunction, SimTypeLong


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
}
