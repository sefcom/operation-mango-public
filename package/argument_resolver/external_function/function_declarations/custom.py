from angr.sim_type import (
    SimTypeFunction,
    SimTypeInt,
    SimTypePointer,
    SimTypeChar,
)


custom_decls = {
    "dprintf": SimTypeFunction(
        [
            SimTypePointer(SimTypeInt(), offset=0),
            SimTypePointer(SimTypeChar(), offset=0),
        ],
        SimTypeInt(signed=True),
        arg_names=["stream", "template"],
        variadic=True,
    ),
    "twsystem": SimTypeFunction(
        [SimTypePointer(SimTypeChar(), offset=0)],
        SimTypeInt(signed=True),
        arg_names=["command"],
    ),
    "execFormatCmd": SimTypeFunction(
        [SimTypePointer(SimTypeChar(), offset=0)],
        SimTypeInt(signed=True),
        arg_names=["command"],
    ),
    "exec_cmd": SimTypeFunction(
        [SimTypePointer(SimTypeChar(), offset=0)],
        SimTypeInt(signed=True),
        arg_names=["command"],
    ),
    "tp_systemEx": SimTypeFunction(
        [SimTypePointer(SimTypeChar(), offset=0)],
        SimTypeInt(signed=True),
        arg_names=["command"],
    ),
    "___system": SimTypeFunction(
        [SimTypePointer(SimTypeChar(), offset=0)],
        SimTypeInt(signed=True),
        arg_names=["command"],
    ),
    "bstar_system": SimTypeFunction(
        [SimTypePointer(SimTypeChar(), offset=0)],
        SimTypeInt(signed=True),
        arg_names=["command"],
    ),
    "doSystemCmd": SimTypeFunction(
        [SimTypePointer(SimTypeChar(), offset=0)],
        SimTypeInt(signed=True),
        arg_names=["command"],
    ),
    "doShell": SimTypeFunction(
        [SimTypePointer(SimTypeChar(), offset=0)],
        SimTypeInt(signed=True),
        arg_names=["command"],
    ),
    "CsteSystem": SimTypeFunction(
        [SimTypePointer(SimTypeChar(), offset=0)],
        SimTypeInt(signed=True),
        arg_names=["command"],
    ),
    "cgi_deal_popen": SimTypeFunction(
        [SimTypePointer(SimTypeChar(), offset=0)],
        SimTypeInt(signed=True),
        arg_names=["command"],
    ),
    "ExeCmd": SimTypeFunction(
        [SimTypePointer(SimTypeChar(), offset=0)],
        SimTypeInt(signed=True),
        arg_names=["command"],
    ),
    "ExecShell": SimTypeFunction(
        [SimTypePointer(SimTypeChar(), offset=0)],
        SimTypeInt(signed=True),
        arg_names=["command"],
    ),
    "exec_shell_popen": SimTypeFunction(
        [SimTypePointer(SimTypeChar(), offset=0)],
        SimTypeInt(signed=True),
        arg_names=["command"],
    ),
    "exec_shell_popen_str": SimTypeFunction(
        [SimTypePointer(SimTypeChar(), offset=0)],
        SimTypeInt(signed=True),
        arg_names=["command"],
    ),
    "exec_shell_async": SimTypeFunction(
        [SimTypePointer(SimTypeChar(), offset=0)],
        SimTypeInt(signed=True),
        arg_names=["command"],
    ),
    "exec_shell_sync": SimTypeFunction(
        [SimTypePointer(SimTypeChar(), offset=0)],
        SimTypeInt(signed=True),
        arg_names=["command"],
    ),
    "exec_shell_sync2": SimTypeFunction(
        [SimTypePointer(SimTypeChar(), offset=0)],
        SimTypeInt(signed=True),
        arg_names=["command"],
    ),
    "nflog_get_payload": SimTypeFunction(
        [
            SimTypePointer(SimTypeChar(), offset=0),
            SimTypePointer(SimTypeChar(), offset=0),
            SimTypePointer(SimTypeChar(), offset=0),
        ],
        SimTypeInt(signed=True),
    ),
    "query_param_parser": SimTypeFunction(
        [
            SimTypePointer(SimTypeChar(), offset=0),
            SimTypePointer(SimTypeChar(), offset=0),
            SimTypePointer(SimTypeChar(), offset=0),
        ],
        SimTypeInt(signed=True),
    ),
    "GetValue": SimTypeFunction(
        [
            SimTypePointer(SimTypeChar(), offset=0),
            SimTypePointer(SimTypeChar(), offset=0),
        ],
        SimTypeInt(signed=True),
    ),
    "SetValue": SimTypeFunction(
        [
            SimTypePointer(SimTypeChar(), offset=0),
            SimTypePointer(SimTypeChar(), offset=0),
        ],
        SimTypeInt(signed=True),
    ),
    "httpSetEnv": SimTypeFunction(
        [
            SimTypePointer(SimTypeChar(), offset=0),
            SimTypePointer(SimTypeChar(), offset=0),
        ],
        SimTypeInt(signed=True),
    ),
}
