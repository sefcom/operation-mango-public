import functools

from collections import defaultdict
from typing import TYPE_CHECKING, Dict, List, Set

from angr.analyses.reaching_definitions.function_handler import FunctionHandler, FunctionCallData

from angr.knowledge_plugins.key_definitions.atoms import Atom, Register
from angr.knowledge_plugins.functions import Function

from argument_resolver.utils.calling_convention import CallingConventionResolver
from argument_resolver.utils.utils import Utils
from argument_resolver.formatters.log_formatter import make_logger

from argument_resolver.utils.stored_function import StoredFunction
import claripy

if TYPE_CHECKING:
    from archinfo import Arch
    from angr import Project
    from angr.analyses.reaching_definitions.rd_state import (
        ReachingDefinitionsState,
        Definition,
    )
    from angr.code_location import CodeLocation


def get_arg_vals(arg_atoms: List[Atom], state: "ReachingDefinitionsState"):
    vals = {}
    for atom in arg_atoms:
        value = state.live_definitions.get_value_from_atom(atom)
        if value is not None:
            vals[atom] = value
        else:
            vals[atom] = Utils.unknown_value_of_unknown_size(state, atom, state.current_codeloc)
    return vals


class HandlerBase(FunctionHandler):

    MAX_READ_SIZE = 0x20

    def __init__(
        self,
        project: "Project",
        sink_function: "Function" = None,
        sink_atoms: List[Atom] = None,
        env_dict: Dict = None,
        assumed_execution: bool = True,
        taint_trace: bool = False,
        forward_trace: bool = False,
        max_local_call_depth: int = 3,
        progress_callback=None
    ):
        """
        :param project:
        :param sink_function:
        :param sink_atoms:
        """
        self._project = project
        self._calling_convention_resolver = None
        self._rda = None
        self._sink_function_addr = sink_function.addr if sink_function else None
        self.call_trace = []
        self.call_stack = []
        self.analyzed_list = []
        self.env_dict = env_dict
        self.current_parent: StoredFunction = None
        self.in_local_handler = False
        self.assumed_execution = assumed_execution
        self.taint_trace = taint_trace
        self.forward_trace = forward_trace
        self.first_run = True
        self.max_local_call_depth = max_local_call_depth
        self.progress_callback = progress_callback
        self.fd_tracker = {
            0: {"val": claripy.BVS('"stdin"', self._project.arch.bits, explicit_name=True), "parent": None, "ins_addr": None},
            1: {"val": claripy.BVS('"stdout"', self._project.arch.bits, explicit_name=True), "parent": None, "ins_addr": None},
            2: {"val": claripy.BVS('"stderr"', self._project.arch.bits, explicit_name=True), "parent": None, "ins_addr": None},
        }
        for fd_dict in self.fd_tracker.values():
            fd_dict["val"].variables = frozenset(set(fd_dict["val"].variables) | {"TOP"})

        self.env_access = set()
        self.keyword_access = {}

        self._sink_atoms = sink_atoms
        self.sink_atom_defs: Dict[Atom, Set["Definition"]] = defaultdict(set)
        self.log = make_logger()

    def gen_fd(self):
        return max(x for x in self.fd_tracker if isinstance(x, int)) + 1

    @staticmethod
    def _balance_stack_before_returning(
        state: "ReachingDefinitionsState", codeloc: "CodeLocation"
    ) -> None:
        arch: "Arch" = state.arch
        if arch.call_pushes_ret:
            # pops ret
            sp_atom = Register(arch.sp_offset, arch.bytes)
            sp_defs = state.get_definitions(sp_atom)
            if sp_defs:
                sp_def = next(iter(sp_defs))
                sp_data = state.registers.load(
                    sp_def.atom.reg_offset, size=arch.bytes
                )
                state.kill_and_add_definition(sp_atom, sp_data)

    @staticmethod
    def returns(func):
        @functools.wraps(func)
        def wrapped_func(
            self,
            state: "ReachingDefinitionsState",
            stored_func: StoredFunction,
            *args,
            **kwargs,
        ):

            analysed, new_state, ret_val = func(self, state, stored_func, *args, **kwargs)
            stored_func.handle_ret(new_state=new_state, value=ret_val)

            return analysed, new_state

        return wrapped_func

    @staticmethod
    def tag_parameter_definitions(func):
        """
        Add a `ParameterTag` to the definitions of the arguments of the function simulated by the handler.
        """

        @functools.wraps(func)
        def wrapper(self, state: "ReachingDefinitionsState", data: FunctionCallData):
            if data.function is None:
                return False, state
            stored_func = self.call_trace[-1]
            stored_func.tag_params(first_run=self.first_run)
            return func(self, state, stored_func)

        return wrapper

    def hook(self, rda):
        self._rda = rda
        self._calling_convention_resolver = CallingConventionResolver(
            rda.project,
            rda.project.arch,
            rda.kb.functions,
        )
        return self

    def handle_external_function(self, state: "ReachingDefinitionsState", data: FunctionCallData):
        self.handle_local_function(state, data)

    def handle_function(self, state: "ReachingDefinitionsState", data: FunctionCallData):
        depth = self.current_parent.depth if self.current_parent else 0
        stored_func = StoredFunction(state, data, self.call_stack, depth)
        if stored_func.function is None:
            return
        self.call_trace.append(stored_func)
        was_first_run = self.first_run
        super().handle_function(state, data)
        stored_func.return_definitions = state.analysis.function_calls[data.callsite_codeloc].ret_defns
        if was_first_run:
            stored_func.definitions = set().union(*[state.get_definitions(atom) for atom in stored_func.atoms])
        elif not (stored_func.function.is_plt or stored_func.function.is_simprocedure):
            stored_func.definitions = set().union(*state.analysis.function_calls[data.callsite_codeloc].args_defns)
