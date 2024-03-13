import logging

import claripy
import socket

from typing import List
#
from angr.knowledge_plugins.key_definitions.atoms import Atom, SpOffset, HeapAddress
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues

from argument_resolver.handlers.base import HandlerBase
from argument_resolver.utils.utils import Utils
from argument_resolver.utils.stored_function import StoredFunction

from archinfo import Endness


class NetworkHandlers(HandlerBase):
    """
    Handlers for network functions
        inet_ntoa,
    """

    def __init__(self, *args, **kwargs):
        self.ntoa_buf = None
        super().__init__(*args, **kwargs)


    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_accept(
            self,
            state: "ReachingDefinitionsState",
            stored_func: StoredFunction,
    ):

        self.log.debug("RDA: %s(), ins_addr=%#x", stored_func.name, stored_func.code_loc.ins_addr)
        cc = self._calling_convention_resolver.get_cc(stored_func.name)

        sock_fd = cc.get_next_arg()
        fd_val = Utils.get_values_from_cc_arg(sock_fd, state, state.arch)
        out_val = [str(x.concrete_value) if x.concrete else str(x) for x in Utils.get_values_from_multivalues(fd_val)]

        ret_fd = self.gen_fd()
        possible_parents = [x.concrete_value for x in Utils.get_values_from_multivalues(fd_val) if x.concrete]
        self.fd_tracker[ret_fd] = {"val": claripy.BVS(f"{stored_func.name}(fd: {' | '.join(sorted(out_val))})@0x{stored_func.code_loc.ins_addr:x}", state.arch.bits), "parent": possible_parents, "ins_addr": None}

        return True, state, MultiValues(claripy.BVV(ret_fd, state.arch.bits))

    def _handle_recv(
            self,
            state: "ReachingDefinitionsState",
            stored_func: StoredFunction,
    ):

        self.log.debug("RDA: %s(), ins_addr=%#x", stored_func.name, stored_func.code_loc.ins_addr)
        cc = self._calling_convention_resolver.get_cc(stored_func.name)

        sock_fd = cc.get_next_arg()
        buf = cc.get_next_arg()
        len_ = cc.get_next_arg()

        fd_val = Utils.get_values_from_cc_arg(sock_fd, state, state.arch)
        buf_addr = Utils.get_values_from_cc_arg(buf, state, state.arch)
        len_val = Utils.get_values_from_cc_arg(len_, state, state.arch)
        len_max = state.arch.bytes
        for len_v in Utils.get_values_from_multivalues(len_val):
            if len_v.concrete:
                len_max = max(len_max, len_v.concrete_value)

        len_max = min(len_max if len_max > 0 else 0, self.MAX_READ_SIZE)
        mem_locs = []
        for ptr in Utils.get_values_from_multivalues(buf_addr):
            try:
                sp = state.get_sp()
            except AssertionError:
                sp = state.arch.initial_sp

            if not Utils.is_pointer(ptr, sp, self._project):
                continue

            if state.is_stack_address(ptr):
                offset = state.get_stack_offset(ptr)
                if offset is None:
                    continue
                mem_locs.append(Atom.mem(SpOffset(state.arch.bits, offset), len_max, endness=Endness.BE))
            elif state.is_heap_address(ptr):
                offset = state.get_heap_offset(ptr)
                if offset is None:
                    continue
                mem_locs.append(Atom.mem(HeapAddress(offset), len_max, endness=Endness.BE))
            elif ptr.concrete:
                mem_locs.append(Atom.mem(ptr.concrete_value, len_max, endness=Endness.BE))

        parent_fds = []
        parent = None
        for val in Utils.get_values_from_multivalues(fd_val):
            if val.concrete and val.concrete_value in self.fd_tracker:
                parent_fds.append(val.concrete_value)
                if parent is None:
                    parent = self.fd_tracker[val.concrete_value]["val"]
                else:
                    parent = parent.concat(self.fd_tracker[val.concrete_value]["val"])

        if parent is not None:
            parent_name = next(iter(x for x in parent.variables if x != "TOP"))
        else:
            parent_name = "?"

        if stored_func.name not in self.fd_tracker:
            self.fd_tracker[stored_func.name] = []

        for mem in mem_locs:
            buf_bvs = claripy.BVS(
                f"{stored_func.name}({parent_name})@0x{stored_func.code_loc.ins_addr:x}",
                mem.size * 8)
            buf_bvs.variables = frozenset(set(buf_bvs.variables) | {"TOP"})
            self.fd_tracker[stored_func.name].append({"val": buf_bvs, "parent": parent_fds, "ins_addr": stored_func.code_loc.ins_addr})
            stored_func.depends(mem, *stored_func.atoms, value=MultiValues(buf_bvs), apply_at_callsite=True)

        return True, state, MultiValues(claripy.BVV(len_max, state.arch.bits))

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_recv(
            self,
            state: "ReachingDefinitionsState",
            stored_func: StoredFunction,
    ):
        return self._handle_recv(state, stored_func)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_recvfrom(
            self,
            state: "ReachingDefinitionsState",
            stored_func: StoredFunction,
    ):
        return self._handle_recv(state, stored_func)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_nflog_get_payload(
            self,
            state: "ReachingDefinitionsState",
            stored_func: StoredFunction,
    ):
        return self._handle_recv(state, stored_func)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_socket(
            self,
            state: "ReachingDefinitionsState",
            stored_func: StoredFunction,
    ):

        self.log.debug("RDA: %s(), ins_addr=%#x", stored_func.name, stored_func.code_loc.ins_addr)
        cc = self._calling_convention_resolver.get_cc(stored_func.name)

        domain = cc.get_next_arg()
        sock_type = cc.get_next_arg()
        protocol = cc.get_next_arg()

        domain_val = Utils.get_values_from_cc_arg(domain, state, state.arch)
        type_val = Utils.get_values_from_cc_arg(sock_type, state, state.arch)
        protocol_val = Utils.get_values_from_cc_arg(protocol, state, state.arch)

        known_domain = {
            socket.AF_UNIX: "AF_UNIX",
            socket.AF_INET: "AF_INET",
            socket.AF_INET6: "AF_INET6",
        }

        known_type = {
            socket.SOCK_STREAM: "SOCK_STREAM",
            socket.SOCK_DGRAM: "SOCK_DGRAM",
            socket.SOCK_RAW: "SOCK_RAW",
        }

        def get_val_list(val, val_dict) -> List[str]:
            out_vals = []
            for v in Utils.get_values_from_multivalues(val):
                if v.concrete:
                    if v.concrete_value in val_dict:
                        out_vals.append(val_dict[v.concrete_value])
                    else:
                        out_vals.append(hex(v.concrete_value))
                else:
                    out_vals.append(str(v))
            return out_vals

        domain_vals = get_val_list(domain_val, known_domain)
        type_vals = get_val_list(type_val, known_type)
        protocol_vals = [str(x.concrete_value) if x.concrete else str(x) for x in Utils.get_values_from_multivalues(protocol_val)]

        ret_fd = self.gen_fd()

        self.fd_tracker[ret_fd] = {"val": claripy.BVS(f"{stored_func.name}({' | '.join(sorted(domain_vals))}, {' | '.join(sorted(type_vals))}, {' | '.join(sorted(protocol_vals))})", state.arch.bits), "parent": None, "ins_addr": None}

        return True, state, MultiValues(claripy.BVV(ret_fd, state.arch.bits))

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_inet_ntoa(
           self,
           state: "ReachingDefinitionsState",
           stored_func: StoredFunction,
           handler_name: str = "inet_ntoa",
    ):
        """
        Hard codes the return address of 127.1.1.1
        """

        self.log.debug("RDA: %s(), ins_addr=%#x", handler_name, stored_func.code_loc.ins_addr)

        cc = self._calling_convention_resolver.get_cc(handler_name)
        if self.ntoa_buf is None:
            val = MultiValues(claripy.BVV("127.1.1.1"))

            size = Utils.get_size_from_multivalue(val)
            heap_addr = state.heap_allocator.allocate(size)
            memloc = Atom.mem(heap_addr, size, endness=Endness.BE)
            stored_func.depends(memloc, value=val)
            heap_mv = MultiValues(Utils.gen_heap_address(heap_addr.value, state.arch))
            self.ntoa_buf = heap_mv

        return True, state, self.ntoa_buf