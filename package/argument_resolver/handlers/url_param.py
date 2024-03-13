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

import claripy


class URLParamHandlers(HandlerBase):

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_custom_param_parser(self, state: ReachingDefinitionsState, stored_func: StoredFunction):
        """
        Process read and marks it as taint
        .. sourcecode:: c
            int open(char *path, const char *mode);
        :param stored_func:
        :param state: Register and memory definitions and uses
        """
        self.log.debug("RDA: fgets(), ins_addr=%#x", stored_func.code_loc.ins_addr)

        arch = state.arch
        cc = self._calling_convention_resolver.get_cc("query_param_parser")

        if len(stored_func.function.prototype.args) == 1:
            src = None
            param = cc.get_next_arg()
            dst = None
        else:
            src = cc.get_next_arg()
            param = cc.get_next_arg()
            dst = cc.get_next_arg()

        param_ptr = Utils.get_values_from_cc_arg(param, state, arch)
        params = Utils.get_strings_from_pointers(param_ptr, state, stored_func.code_loc)

        param_list = []
        for p in Utils.get_values_from_multivalues(params):
            if p.concrete:
                found_param = Utils.bytes_from_int(p).decode("latin-1")
                param_list.append(found_param)

        buf_bvs = claripy.BVS(f'frontend_param("{", ".join(param_list)}")@0x{stored_func.code_loc.ins_addr:x}',
                              self.MAX_READ_SIZE * 8)
        buf_bvs.variables = frozenset(set(buf_bvs.variables) | {"TOP"})
        self.keyword_access[buf_bvs] = param_list

        mv = MultiValues(buf_bvs)
        if dst:
            dst_ptr = Utils.get_values_from_cc_arg(dst, state, arch)
            if len(stored_func.function.prototype.args) > 2:
                for dst in Utils.get_values_from_multivalues(dst_ptr):
                    if not state.is_top(dst):
                        memloc = MemoryLocation(Utils.get_store_method_from_ptr(dst, state), Utils.get_size_from_multivalue(mv))
                        sources = {cc_to_rd(src, state.arch, state)} if src else set()
                        stored_func.depends(memloc, *sources, value=mv)

        return True, state, mv
