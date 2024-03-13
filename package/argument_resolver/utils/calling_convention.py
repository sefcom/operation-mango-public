import logging

from typing import Dict, List, Union, Optional, Tuple, TYPE_CHECKING

from angr.calling_conventions import (
    SimFunctionArgument,
    SimRegArg,
    SimStackArg,
    DEFAULT_CC,
    SimCC,
)
from angr.sim_type import SimTypePointer, SimTypeChar

from angr.engines.light import SpOffset
from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation, Register
from angr.knowledge_plugins.functions.function_manager import FunctionManager
from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions
from angr.procedures.definitions.glibc import _libc_decls
from archinfo.arch import Arch

from argument_resolver.utils.utils import Utils
from argument_resolver.external_function.function_declarations import CUSTOM_DECLS

if TYPE_CHECKING:
    from angr.sim_type import SimTypeFunction


LOGGER = logging.getLogger("FastFRUIT")

LIBRARY_DECLS = {**_libc_decls, **CUSTOM_DECLS}


def get_default_cc_with_args(num_args: int, arch: Arch, is_win=False) -> SimCC:
    """
    Get the default calling convention, containing where the arguments are located when the function is called, and
    where the return value will be placed.

    Query angr.calling_convention.DEFAULT_CC to recover the calling convention corresponding to the given arch, and
    compute the argument positions whenever they appear on the stack.

    :param num_args: The number of arguments the function takes.
    :param arch: The architecture of the binary where the studied function is.
    :return: The calling convention.
    """

    def compute_offset(arch, default_cc, offset):
        def is_mips(arch):
            return arch.name.lower().find("mips") > -1

        initial_offset = 1 if arch.call_pushes_ret else 0
        mips_offset = (
            len(default_cc.ARG_REGS + default_cc.FP_ARG_REGS) if is_mips(arch) else 0
        )
        return arch.bytes * (offset + mips_offset + initial_offset)

    platform_name = "Linux" if not is_win else "Win32"
    default_cc = DEFAULT_CC[arch.name][platform_name]

    reg_args = [SimRegArg(x, arch.bytes) for x in default_cc.ARG_REGS[:num_args]]
    stack_args: List[SimFunctionArgument] = list(
        map(
            lambda offset: SimStackArg(
                compute_offset(arch, default_cc, offset), arch.bits
            ),
            range(num_args - len(reg_args)),
        )
    )
    cc = SimCC.find_cc(arch, reg_args + stack_args, default_cc.STACKARG_SP_DIFF)
    if cc is None:
        cc = default_cc(arch)
    return cc


def cc_to_rd(
    sim: SimFunctionArgument, arch: Arch, state=None
) -> Union[Register, MemoryLocation]:
    """
    Conversion to Register and SpOffset from respectively angr/calling_conventions' SimRegArg and SimStackArg.

    The arch parameter is necessary to create the Register, as its constructor needs an offset and a size.

    :param sim: Input register or stack offset
    :param arch: Architecture
    :return: Output register or stack offset
    """
    if isinstance(sim, SimRegArg):
        offset, size = arch.registers[sim.reg_name]
        return Register(offset, size, arch)
    if isinstance(sim, SimStackArg):
        if state is not None:
            initial_sp = (
                LiveDefinitions.INITIAL_SP_64BIT
                if arch.bits == 64
                else LiveDefinitions.INITIAL_SP_32BIT
            )
            return MemoryLocation(
                SpOffset(
                    sim.size, (Utils.get_sp(state) - initial_sp) + sim.stack_offset
                ),
                sim.size,
                endness=arch.memory_endness,
            )
        else:
            return MemoryLocation(
                SpOffset(sim.size, sim.stack_offset),
                sim.size,
                endness=arch.memory_endness,
            )
    else:
        raise TypeError(f"Expected SimRegArg or SimStackArg, got {type(sim).__name__}")


def get_next_arg(self):
    if hasattr(self, "sim_func"):
        if self.arg_counter >= len(self.sim_func.args):
            if len(self.sim_func.args) > 0:
                arg = self.next_arg(
                    self.session, self.sim_func.args[-1].with_arch(self.ARCH)
                )
            else:
                arg = self.next_arg(
                    self.session, SimTypePointer(SimTypeChar).with_arch(self.ARCH)
                )
        else:
            arg = self.next_arg(
                self.session, self.sim_func.args[self.arg_counter].with_arch(self.ARCH)
            )
            self.arg_counter += 1
    else:
        arg = self.next_arg(
            self.session, SimTypePointer(SimTypeChar).with_arch(self.ARCH)
        )
    return arg


class CallingConventionResolver:
    """
    Query calling conventions for the functions we are interested in.
    """

    def __init__(
        self,
        project,
        arch: Arch,
        functions: FunctionManager,
    ):
        """
        :param arch: The architecture targeted by the analysed binary.
        :param functions: Function manager that includes all functions of the binary.
        :param variable_recovery_fast: The <VariableRecoveryFast> analysis from the ongoing <Project>.
        """
        self._project = project
        self._arch = arch
        self._functions = functions

        self._cc: Dict[str, SimCC] = {}
        self._prototypes: Dict[str, Optional["SimTypeFunction"]] = {}

    def _get_cc_and_proto(
        self, function_name
    ) -> Tuple[Optional[SimCC], Optional["SimTypeFunction"]]:
        cc, proto = None, None

        if function_name in LIBRARY_DECLS:
            number_of_parameters = len(LIBRARY_DECLS[function_name].args)
            cc = get_default_cc_with_args(
                number_of_parameters,
                self._arch,
                is_win=len(self._project.loader.all_pe_objects) > 0,
            )
            cc.sim_func = LIBRARY_DECLS[function_name]

            # attempt to use CallingConventionAnalysis to get its prototype
            func = self._functions.function(name=function_name)
            if func is not None:
                cc_analysis = self._project.analyses.CallingConvention(func)
                proto = cc_analysis.prototype
            else:
                proto = cc.sim_func
        elif function_name in self._functions:
            func = self._functions[function_name]
            self._project.analyses.VariableRecoveryFast(func)
            cc_analysis = self._project.analyses.CallingConvention(func)
            if cc_analysis.cc is None:
                LOGGER.error("CCA: Failed for %s()", function_name)
            else:
                cc = cc_analysis.cc
                proto = cc_analysis.prototype
                cc.sim_func = LIBRARY_DECLS[function_name]
                # LOGGER.debug("CCA: %s() with arguments %s", function_name, cc.args)
        else:
            LOGGER.error(
                "CCA: Failed for %s(), function neither an external function nor have its name in CFG",
                function_name,
            )
        setattr(SimCC, "get_next_arg", get_next_arg)

        return cc, proto

    def get_cc(self, function_name: str) -> Optional[SimCC]:
        """
        Return calling convention given the name of a function.

        :param function_name: The function's name
        :return:              The Calling convention (from angr)
        """
        if function_name not in self._cc:
            (
                self._cc[function_name],
                self._prototypes[function_name],
            ) = self._get_cc_and_proto(function_name)
        if self._cc[function_name] is not None:
            self._cc[function_name].session = self._cc[function_name].arg_session(None)
            self._cc[function_name].arg_counter = 0
        return self._cc[function_name]

    def get_prototype(self, function_name: str) -> Optional["SimTypeFunction"]:
        """
        Return the function prototype given the name of a function.

        :param function_name: Function name
        :return:              The function prototype
        """
        if function_name not in self._cc:
            (
                self._cc[function_name],
                self._prototypes[function_name],
            ) = self._get_cc_and_proto(function_name)
        return self._prototypes[function_name]
