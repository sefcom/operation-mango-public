from .input_functions import INPUT_EXTERNAL_FUNCTIONS, KEY_BEACONS
from .sink import VULN_TYPES, Sink
from .function_declarations import CUSTOM_DECLS


def is_an_external_input_function(function_name: str) -> bool:
    return any(function_name == x for x in INPUT_EXTERNAL_FUNCTIONS)
