from angr.sim_type import (
    SimTypeFunction,
    SimTypeInt,
    SimTypePointer,
    SimTypeChar,
    SimTypeBottom,
)


libnvram_decls = {
    #
    # Taken from: https://github.com/firmadyne/libnvram/blob/v1.0c/nvram.c .
    #
    # int nvram_set(char *key, char *val);
    "nvram_set": SimTypeFunction(
        [
            SimTypePointer(SimTypeChar(), offset=0),
            SimTypePointer(SimTypeChar(), offset=0),
        ],
        SimTypeInt(signed=True),
        arg_names=["key", "val"],
    ),
    # char *nvram_get(char *key);
    "nvram_get": SimTypeFunction(
        [SimTypePointer(SimTypeChar(), offset=0)],
        SimTypePointer(SimTypeChar(), offset=0),
        arg_names=["key"],
    ),
    # char *nvram_safe_get(char *key);
    "nvram_safe_get": SimTypeFunction(
        [SimTypePointer(SimTypeChar(), offset=0)],
        SimTypePointer(SimTypeChar(), offset=0),
        arg_names=["key"],
    ),
    # int nvram_set(char *key, char *val);
    "nvram_safe_set": SimTypeFunction(
        [
            SimTypePointer(SimTypeChar(), offset=0),
            SimTypePointer(SimTypeChar(), offset=0),
        ],
        SimTypeInt(signed=True),
        arg_names=["key", "val"],
    ),
    #
    # Taken from: https://github.com/firmadyne/libnvram/blob/v1.0c/alias.c .
    #
    # int acosNvramConfig_set(char *key, char *val)
    "acosNvramConfig_set": SimTypeFunction(
        [
            SimTypePointer(SimTypeChar(), offset=0),
            SimTypePointer(SimTypeChar(), offset=0),
        ],
        SimTypeInt(signed=True),
        arg_names=["key", "val"],
    ),
    # char *acosNvramConfig_get(char *key)
    "acosNvramConfig_get": SimTypeFunction(
        [SimTypePointer(SimTypeChar(), offset=0)],
        SimTypePointer(SimTypeChar(), offset=0),
        arg_names=["key"],
    ),
    "acosNvramConfig_read": SimTypeFunction(
        [SimTypePointer(SimTypeChar(), offset=0)],
        SimTypePointer(SimTypeChar(), offset=0),
        SimTypePointer(SimTypeInt(), offset=0),
        arg_names=["key"],
    ),
    #"acosNvramConfig_write": SimTypeFunction(
    #    [SimTypePointer(SimTypeChar(), offset=0)],
    #    SimTypePointer(SimTypeChar(), offset=0),
    #    SimTypePointer(SimTypeInt(), offset=0),
    #    arg_names=["key"],
    #),
    #
    # Custom Definitions
    #
    #
    "bcm_nvram_get": SimTypeFunction(
        [SimTypePointer(SimTypeChar(), offset=0)],
        SimTypeBottom(label="void"),
        arg_names=["name"],
    ),
    "bcm_nvram_set": SimTypeFunction(
        [
            SimTypePointer(SimTypeChar(), offset=0),
            SimTypePointer(SimTypeChar(), offset=0),
        ],
        SimTypeBottom(label="void"),
        arg_names=["name", "value"],
    ),
    "envram_get": SimTypeFunction(
        [SimTypePointer(SimTypeChar(), offset=0)],
        SimTypeBottom(label="void"),
        arg_names=["name"],
    ),
    "envram_set": SimTypeFunction(
        [
            SimTypePointer(SimTypeChar(), offset=0),
            SimTypePointer(SimTypeChar(), offset=0),
        ],
        SimTypeBottom(label="void"),
        arg_names=["name", "value"],
    ),
    "wlcsm_nvram_get": SimTypeFunction(
        [SimTypePointer(SimTypeChar(), offset=0)],
        SimTypeBottom(label="void"),
        arg_names=["name"],
    ),
    "wlcsm_nvram_set": SimTypeFunction(
        [
            SimTypePointer(SimTypeChar(), offset=0),
            SimTypePointer(SimTypeChar(), offset=0),
        ],
        SimTypeBottom(label="void"),
        arg_names=["name", "value"],
    ),
    "dni_nvram_get": SimTypeFunction(
        [SimTypePointer(SimTypeChar(), offset=0)],
        SimTypeBottom(label="void"),
        arg_names=["name"],
    ),
    "dni_nvram_set": SimTypeFunction(
        [
            SimTypePointer(SimTypeChar(), offset=0),
            SimTypePointer(SimTypeChar(), offset=0),
        ],
        SimTypeBottom(label="void"),
        arg_names=["name", "value"],
    ),
    "PTI_nvram_get": SimTypeFunction(
        [SimTypePointer(SimTypeChar(), offset=0)],
        SimTypeBottom(label="void"),
        arg_names=["name"],
    ),
    "PTI_nvram_set": SimTypeFunction(
        [
            SimTypePointer(SimTypeChar(), offset=0),
            SimTypePointer(SimTypeChar(), offset=0),
        ],
        SimTypeBottom(label="void"),
        arg_names=["name", "value"],
    ),
}
