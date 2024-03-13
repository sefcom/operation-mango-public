import os

from angr.code_location import ExternalCodeLocation
from angr.calling_conventions import SimRegArg, SimStackArg
from angr.engines.light import SpOffset
from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.knowledge_plugins.key_definitions.tag import (
    ReturnValueTag,
    SideEffectTag,
    InitialValueTag,
)
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues

from argument_resolver.formatters.log_formatter import make_logger
from argument_resolver.handlers.base import HandlerBase
from argument_resolver.utils.calling_convention import cc_to_rd
from argument_resolver.utils.utils import Utils
from argument_resolver.utils.stored_function import StoredFunction

from archinfo import Endness

import claripy


class UnistdHandlers(HandlerBase):

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_open(self, state: ReachingDefinitionsState, stored_func: StoredFunction):
        """
        Process read and marks it as taint
        .. sourcecode:: c
            int open(char *path, const char *mode);
        :param stored_func:
        :param state: Register and memory definitions and uses
        """
        self.log.debug("RDA: fgets(), ins_addr=%#x", stored_func.code_loc.ins_addr)

        arch = state.arch
        cc = self._calling_convention_resolver.get_cc("fread")

        arg_path = cc.get_next_arg()
        arg_mode = cc.get_next_arg()

        path_ptrs = Utils.get_values_from_cc_arg(arg_path, state, arch)
        mode = Utils.get_values_from_cc_arg(arg_mode, state, arch)
        known_modes = {
            os.O_RDONLY: "r",
            os.O_WRONLY: "w",
            os.O_RDWR: "rw",
        }

        path = Utils.get_strings_from_pointers(path_ptrs, state, stored_func.code_loc)
        paths = []
        for p in Utils.get_values_from_multivalues(path):
            if p.concrete:
                paths.append(f'"{Utils.bytes_from_int(p).decode("latin-1")}"')
            else:
                paths.append(f'"{p}"')

        modes = []
        for m in Utils.get_values_from_multivalues(mode):
            if m.concrete:
                modes.append(f'"{known_modes.get(m.concrete_value, m.concrete_value)}"')
            else:
                modes.append(f'"{m}"')

        fd = self.gen_fd()
        buf_bvs = claripy.BVS(f"{stored_func.name}({' | '.join(paths)}, {' | '.join(modes)})@0x{stored_func.code_loc.ins_addr:x}",
                    state.arch.bits)
        buf_bvs.variables = frozenset(set(buf_bvs.variables) | {"TOP"})
        self.fd_tracker[fd] = {"val": buf_bvs, "parent": None, "ins_addr": None}

        return True, state, MultiValues(claripy.BVV(fd, state.arch.bits))


    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_read(
        self,
        state: "ReachingDefinitionsState",
        stored_func: StoredFunction,
    ):
        """
        Process read and marks it as taint
        .. sourcecode:: c
            size_t read(int fd, void *buf, size_t count);
        :param ReachingDefinitionsState state:    reaching definitions state
        :param Codeloc codeloc:              Code location of the call
        :param handler_name:                 Name of function to handle
        """
        self.log.debug("RDA: %s(), ins_addr=%#x", stored_func.name, stored_func.code_loc.ins_addr)

        cc = self._calling_convention_resolver.get_cc("read")

        # get args
        fd = cc.get_next_arg()  # fd
        arg_buf = cc.get_next_arg()
        arg_size = cc.get_next_arg()

        # get buf
        fd_vals = Utils.get_values_from_cc_arg(fd, state, state.arch)
        buf_ptrs = Utils.get_values_from_cc_arg(arg_buf, state, state.arch)

        # get count/size
        size_values = Utils.get_values_from_cc_arg(arg_size, state, state.arch)


        parent = None
        parent_fds = []
        for val in Utils.get_values_from_multivalues(fd_vals):
            if val.concrete and val.concrete_value in self.fd_tracker:
                parent_fds.append(val.concrete_value)
                if parent is None:
                    parent = self.fd_tracker[val.concrete_value]["val"]
                else:
                    parent = parent.concat(self.fd_tracker[val.concrete_value]["val"])

        if stored_func.name not in self.fd_tracker:
            self.fd_tracker[stored_func.name] = []

        for ptr in Utils.get_values_from_multivalues(buf_ptrs):
            for count_val in Utils.get_values_from_multivalues(size_values):
                sp_offset = SpOffset(state.arch.bits, state.get_stack_offset(ptr))
                if sp_offset.offset is None:
                    continue

                if count_val.concrete:
                    size = min(count_val.concrete_value, self.MAX_READ_SIZE)
                    memloc = MemoryLocation(sp_offset, size, endness=Endness.BE)
                else:
                    memloc = MemoryLocation(sp_offset, state.arch.bytes, endness=Endness.BE)

                if parent is not None:
                    parent_name = next(iter(x for x in parent.variables if x != "TOP"))
                else:
                    parent_name = "?"

                buf_bvs = claripy.BVS(
                    f"{stored_func.name}({parent_name})@0x{stored_func.code_loc.ins_addr:x}",
                    memloc.size * 8)
                buf_bvs.variables = frozenset(set(buf_bvs.variables) | {"TOP"})
                self.fd_tracker[stored_func.name].append(
                    {"val": buf_bvs, "parent": parent_fds, "ins_addr": stored_func.code_loc.ins_addr})
                mv = MultiValues(buf_bvs)

                stored_func.depends(memloc, *stored_func.atoms, value=mv)

        return True, state, size_values
