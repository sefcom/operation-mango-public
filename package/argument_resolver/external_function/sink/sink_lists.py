from typing import List

from dataclasses import dataclass


@dataclass
class Sink:
    name: str
    vulnerable_parameters: List[int]


COMMAND_INJECTION_SINKS: List[Sink] = [
    Sink(name="system", vulnerable_parameters=[1]),
    Sink(name="twsystem", vulnerable_parameters=[1]),
    Sink(name="execFormatCmd", vulnerable_parameters=[1]),
    Sink(name="exec_cmd", vulnerable_parameters=[1]),
    Sink(name="___system", vulnerable_parameters=[1]),
    Sink(name="bstar_system", vulnerable_parameters=[1]),
    Sink(name="doSystemCmd", vulnerable_parameters=[1]),
    Sink(name="doShell", vulnerable_parameters=[1]),
    Sink(name="CsteSystem", vulnerable_parameters=[1]),
    Sink(name="cgi_deal_popen", vulnerable_parameters=[1]),
    Sink(name="ExeCmd", vulnerable_parameters=[1]),
    Sink(name="ExecShell", vulnerable_parameters=[1]),
    Sink(name="exec_shell_popen", vulnerable_parameters=[1]),
    Sink(name="exec_shell_popen_str", vulnerable_parameters=[1]),
    Sink(name="popen", vulnerable_parameters=[1]),
    Sink(name="execl", vulnerable_parameters=[1]),
    Sink(name="execlp", vulnerable_parameters=[1]),
    Sink(name="execle", vulnerable_parameters=[1]),
    Sink(name="execv", vulnerable_parameters=[1]),
    Sink(name="execvp", vulnerable_parameters=[1]),
    Sink(name="execvpe", vulnerable_parameters=[1]),
    Sink(name="execve", vulnerable_parameters=[1]),
    Sink(name="tp_systemEx", vulnerable_parameters=[1]),
    Sink(name="exec_shell_async", vulnerable_parameters=[1]),
    Sink(name="exec_shell_sync", vulnerable_parameters=[1]),
    Sink(name="exec_shell_sync2", vulnerable_parameters=[1]),
    Sink(name="SLIBCSystem", vulnerable_parameters=[1]),
    Sink(name="SLIBCExecl", vulnerable_parameters=[2]),
    Sink(name="SLIBCExec", vulnerable_parameters=[1]),
    Sink(name="SLIBCExecv", vulnerable_parameters=[1]),
    Sink(name="SLIBCPopen", vulnerable_parameters=[1]),
    Sink(name="pegaSystem", vulnerable_parameters=[1]),
]

PATH_TRAVERSAL_SINKS: List[Sink] = [
    Sink(name="popen", vulnerable_parameters=[1]),
    Sink(name="fopen", vulnerable_parameters=[1]),
]
# Sink(name="openat", vulnerable_parameters=[1]),
# Sink(name="creat", vulnerable_parameters=[1]),

BUFFER_OVERFLOW_SINKS: List[Sink] = [
    # Sink(name="strcat", vulnerable_parameters=[2]),
    Sink(name="strcpy", vulnerable_parameters=[2]),
    # Sink(name="memcpy", vulnerable_parameters=[2]),
    # Sink(name="gets", vulnerable_parameters=[1]),
]

STRCAT_SINKS: List[Sink] = [
    Sink(name="strcat", vulnerable_parameters=[2]),
]

MEMCPY_SINKS: List[Sink] = [
    Sink(name="memcpy", vulnerable_parameters=[2]),
]

STRING_FORMAT_SINKS: List[Sink] = [
    Sink(name="sprintf", vulnerable_parameters=[2]),
    Sink(name="snprintf", vulnerable_parameters=[3]),
]

GETTER_SINKS: List[Sink] = [
    Sink(name="getenv", vulnerable_parameters=[1]),
    Sink(name="GetValue", vulnerable_parameters=[1]),
    Sink(name="acosNvramConfig_get", vulnerable_parameters=[1]),
    Sink(name="acosNvramConfig_read", vulnerable_parameters=[1]),
    Sink(name="nvram_get", vulnerable_parameters=[1]),
    Sink(name="nvram_safe_get", vulnerable_parameters=[1]),
    Sink(name="bcm_nvram_get", vulnerable_parameters=[1]),
    Sink(name="envram_get", vulnerable_parameters=[1]),
    Sink(name="wlcsm_nvram_get", vulnerable_parameters=[1]),
    Sink(name="dni_nvram_get", vulnerable_parameters=[1]),
    Sink(name="PTI_nvram_get", vulnerable_parameters=[1]),
]

SETTER_SINKS: List[Sink] = [
    Sink(name="setenv", vulnerable_parameters=[2]),
    Sink(name="SetValue", vulnerable_parameters=[1]),
    Sink(name="httpSetEnv", vulnerable_parameters=[1]),
    Sink(name="acosNvramConfig_set", vulnerable_parameters=[2]),
    Sink(name="acosNvramConfig_write", vulnerable_parameters=[2]),
    Sink(name="nvram_set", vulnerable_parameters=[2]),
    Sink(name="nvram_safe_set", vulnerable_parameters=[2]),
    Sink(name="bcm_nvram_set", vulnerable_parameters=[2]),
    Sink(name="envram_set", vulnerable_parameters=[2]),
    Sink(name="wlcsm_nvram_set", vulnerable_parameters=[2]),
    Sink(name="dni_nvram_set", vulnerable_parameters=[2]),
    Sink(name="PTI_nvram_set", vulnerable_parameters=[2]),
]

ENV_SINKS: List[Sink] = GETTER_SINKS + SETTER_SINKS
