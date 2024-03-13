from typing import Union

from .constant_function import ConstantFunction

CONSTANT_FUNCTIONS = [
    ConstantFunction(
        "uname", param_num=1, is_pointer=True, val=b"A" * (0x400 - 1) + b"\x00"
    )
]


def get_constant_function(function_name: str) -> Union[None, ConstantFunction]:
    for func in CONSTANT_FUNCTIONS:
        if func.name == function_name:
            return func
    return None
