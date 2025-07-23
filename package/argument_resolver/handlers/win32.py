import os

from angr.engines.light import SpOffset
from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues

from argument_resolver.handlers.base import HandlerBase
from argument_resolver.utils.utils import Utils
from argument_resolver.utils.stored_function import StoredFunction

from archinfo import Endness

import claripy


class WinHandlers(HandlerBase):

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_ReadConsoleA(self, state: ReachingDefinitionsState, stored_func: StoredFunction):
        """
        Process read and marks it as taint
        .. sourcecode:: c
            int open(char *path, const char *mode);
        :param stored_func:
        :param state: Register and memory definitions and uses
        """
        self.log.debug("RDA: ReadConsoleA, ins_addr=%#x", stored_func.code_loc.ins_addr)

        arch = state.arch
        cc = self._calling_convention_resolver.get_cc("ReadConsoleA")

        fd = cc.get_next_arg()
        buffer_arg = cc.get_next_arg()
        size = cc.get_next_arg()
        size_read = cc.get_next_arg()

        # get buf
        fd_vals = Utils.get_values_from_cc_arg(fd, state, state.arch)
        buf_ptrs = Utils.get_values_from_cc_arg(buffer_arg, state, state.arch)

        # get count/size
        size_values = Utils.get_values_from_cc_arg(size, state, state.arch)

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

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_CreateProcessA(self, state: ReachingDefinitionsState, stored_func: StoredFunction):
        """Handle CreateProcessA - Command Injection Sink"""
        self.log.debug("RDA: CreateProcessA, ins_addr=%#x", stored_func.code_loc.ins_addr)
        
        arch = state.arch
        cc = self._calling_convention_resolver.get_cc("CreateProcessA")
        
        # Extract key parameters (can handle full signature now)
        app_name = cc.get_next_arg()      # lpApplicationName
        cmd_line = cc.get_next_arg()      # lpCommandLine
        prc_attr = cc.get_next_arg()      # lpProcessAttributes
        thrd_attr = cc.get_next_arg()     # lpThreadAttribute
        inhrt_hndl = cc.get_next_arg()    # bInheritHandles
        crt_flags = cc.get_next_arg()     # dwCreationFlags
        env = cc.get_next_arg()           # lpEnvironment
        crnt_dir =  cc.get_next_arg()     # lpCurrentDirectory
        startup_info = cc.get_next_arg()  # lpStartupInfo
        prc_info = cc.get_next_arg()      # lpProcessInformation
        
        # Get command line pointer (main security concern)
        cmd_ptrs = Utils.get_values_from_cc_arg(cmd_line, state, arch)
        
        # Mark as sink dependency (no fd_tracker needed for sinks)
        for ptr in Utils.get_values_from_multivalues(cmd_ptrs):
            sp_offset = SpOffset(state.arch.bits, state.get_stack_offset(ptr))
            if sp_offset.offset is not None:
                memloc = MemoryLocation(sp_offset, 256, endness=Endness.BE)
                stored_func.depends(memloc, *stored_func.atoms)
        
        return True, state, MultiValues(claripy.BVV(1, 32))
    
    
    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_GetCommandLineA(self, state: ReachingDefinitionsState, stored_func: StoredFunction):
        """Handle GetCommandLineA - Zero Parameter Input Source"""
        self.log.debug("RDA: GetCommandLineA, ins_addr=%#x", stored_func.code_loc.ins_addr)
        
        # No parameters to extract
        
        # Create symbolic command line (match ReadConsoleA pattern)
        cmdline_bvs = claripy.BVS(
            f"{stored_func.name}(cmdline)@0x{stored_func.code_loc.ins_addr:x}",
            256 * 8
        )
        cmdline_bvs.variables = frozenset(set(cmdline_bvs.variables) | {"TOP"})
        
        # fd_tracker pattern (match ReadConsoleA)
        if stored_func.name not in self.fd_tracker:
            self.fd_tracker[stored_func.name] = []
        
        self.fd_tracker[stored_func.name].append({
            "val": cmdline_bvs, 
            "parent": [], 
            "ins_addr": stored_func.code_loc.ins_addr
        })
        
        return True, state, MultiValues(cmdline_bvs)


@HandlerBase.returns
@HandlerBase.tag_parameter_definitions
def handle_CreateFileA(self, state: ReachingDefinitionsState, stored_func: StoredFunction):
    """Handle CreateFileA - File Handle Creator"""
    self.log.debug("RDA: CreateFileA, ins_addr=%#x", stored_func.code_loc.ins_addr)
    
    arch = state.arch
    cc = self._calling_convention_resolver.get_cc("CreateFileA")
    
    # Extract parameters (can use full signature now)
    filename = cc.get_next_arg()      # lpFileName
    access = cc.get_next_arg()        # dwDesiredAccess
    share = cc.get_next_arg()         # dwShareMode
    sec_atr = cc.get_next_arg()       # lpSecurityAttributes
    crt_disp = cc.get_next_arg()      # dwCreationDisposition
    flg_atr = cc.get_next_arg()       # dwFlagsAndAttributes
    tmplte_file = cc.get_next_arg()   # hTemplateFile
        
    # Get filename for handle naming
    filename_ptrs = Utils.get_values_from_cc_arg(filename, state, arch)
    
    # Create file handle (not an input source itself)
    file_handle = claripy.BVS(
        f"{stored_func.name}(file)@0x{stored_func.code_loc.ins_addr:x}",
        arch.bits
    )
    file_handle.variables = frozenset(set(file_handle.variables) | {"TOP"})
    
    # Store handle in fd_tracker for future ReadFile operations
    if stored_func.name not in self.fd_tracker:
        self.fd_tracker[stored_func.name] = []
    
    self.fd_tracker[stored_func.name].append({
        "val": file_handle,
        "parent": [],
        "ins_addr": stored_func.code_loc.ins_addr
    })
    
    return True, state, MultiValues(file_handle)


