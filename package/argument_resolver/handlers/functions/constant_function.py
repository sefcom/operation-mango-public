from claripy import BVV

from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation

from argument_resolver.utils.calling_convention import cc_to_rd
from argument_resolver.utils.utils import Utils


class ConstantFunction:
    """
    Represent a function that should return a constant value either through a parameter or return value.
    """

    def __init__(
        self,
        name: str,
        param_num=None,
        is_ret_val=False,
        is_pointer=False,
        val=b"CONSTANT",
    ):
        """
        :param name: The name of the function.
        :param param_num: The index of the parameter (starting from 1) that points to the return value.
        :param is_ret_val: The index of the parameter (starting from 1) that points to the return value.
        :param is_pointer: If the return value should be stored in a memory location.
        :param val: The value to be returned or inserted (defaults to "CONSTANT").
        """
        assert param_num is not None or is_ret_val, "Must have one or the other"

        self.name = name
        self.param_num = param_num
        self.is_ret_val = is_ret_val
        self.is_pointer = is_pointer
        self.val = val
        self.cc = None

    def set_cc(self, calling_convention):
        self.cc = calling_convention

    def constant_handler(self, state, stored_func):
        assert self.cc is not None
        mv = MultiValues(BVV(self.val))

        if self.is_ret_val:
            if state.arch.memory_endness == "Iend_LE":
                self.val = reversed(self.val)
            stored_func.handle_ret(new_state=state, value=self.val)
            return True, state

        if self.param_num:
            for _ in range(self.param_num):
                sim_arg = self.cc.get_next_arg()
            arg = cc_to_rd(sim_arg, state.arch)
            values = Utils.get_values_from_cc_arg(sim_arg, state, state.arch)
            sources = set()
            for val in Utils.get_values_from_multivalues(values):
                mem_loc = MemoryLocation(val, Utils.get_size_from_multivalue(mv))
                sources.add(mem_loc)
                stored_func.depends(mem_loc, value=mv)

            stored_func.depends(arg, *sources, value=values)
            return True, state

    def __repr__(self):
        return f"ConstantFunction: {self.name} Constant Param: {self.param_num} Val: {self.val}"
