from typing import Set

from .sink import VULN_TYPES

# External functions that can be used to provide input to the program.
INPUT_EXTERNAL_FUNCTIONS: Set[str] = {
    "read",
    "fread",
    "fgets",
    "recv",
    "recvfrom",
    "custom_param_parser",
    "ReadConsoleA",
    "GetCommandLineA",
} | {x.name for x in VULN_TYPES["getter"]}

INPUT_EXTERNAL_FUNCTIONS.add("GetEnvironmentVariableA")
INPUT_EXTERNAL_FUNCTIONS.add("AcceptEx")
INPUT_EXTERNAL_FUNCTIONS.add("FindFirstFileA")
INPUT_EXTERNAL_FUNCTIONS.add("GetModuleFileNameA")
INPUT_EXTERNAL_FUNCTIONS.add("ReadProcessMemory")
INPUT_EXTERNAL_FUNCTIONS.add("GetClipboardData")
INPUT_EXTERNAL_FUNCTIONS.add("InternetReadFile")
INPUT_EXTERNAL_FUNCTIONS.add("WSARecv")
INPUT_EXTERNAL_FUNCTIONS.add("WSARecvFrom")


KEY_BEACONS = {
    "REQUEST_METHOD",
    "REQUEST_URI",
    "QUERY_STRING",
    "CONTENT_TYPE",
    "CONTENT_LENGTH",
    "PATH_INFO",
    "SCRIPT_NAME",
    "DOCUMENT_URI",
    "HTTP_ACCEPT_LANGUAGE",
    "HTTP_AUTH",
    "HTTP_AUTHORIZATION",
    "HTTP_CALLBACK",
    "HTTP_COOKIE",
    "HTTP_HNAP_AUTH",
    "HTTP_HOST",
    "HTTP_MTFWU_ACT",
    "HTTP_MTFWU_AUTH",
    "HTTP_NT",
    "HTTP_REFERER",
    "HTTPS",
    "HTTP_SID",
    "HTTP_SOAPACTION",
    "HTTP_ST",
    "HTTP_TIMEOUT",
    "HTTP_USER_AGENT",
}
