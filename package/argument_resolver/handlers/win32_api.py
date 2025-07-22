import claripy
import itertools

from typing import List, Union

from angr.calling_conventions import SimRegArg, SimStackArg
from angr.code_location import CodeLocation
from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation, SpOffset

from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from angr.knowledge_plugins.key_definitions.tag import (
    ParameterTag,
    ReturnValueTag,
    SideEffectTag,
)
from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState

from argument_resolver.formatters.log_formatter import make_logger
from argument_resolver.handlers.base import HandlerBase
from argument_resolver.utils.calling_convention import cc_to_rd
from argument_resolver.utils.utils import Utils
from argument_resolver.utils.stored_function import StoredFunction

from archinfo import Endness


class Win32ApiHandlers(HandlerBase):
    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_CreateProcessA(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        """
        Handle CreateProcessA Win32 API call
        
        BOOL CreateProcessA(
            LPCSTR                lpApplicationName,     // arg 0
            LPSTR                 lpCommandLine,         // arg 1  
            LPSECURITY_ATTRIBUTES lpProcessAttributes,   // arg 2
            LPSECURITY_ATTRIBUTES lpThreadAttributes,    // arg 3
            BOOL                  bInheritHandles,       // arg 4
            DWORD                 dwCreationFlags,       // arg 5
            LPVOID                lpEnvironment,         // arg 6
            LPCSTR                lpCurrentDirectory,    // arg 7
            LPSTARTUPINFOA        lpStartupInfo,         // arg 8
            LPPROCESS_INFORMATION lpProcessInformation   // arg 9
        );
        """
        self.log.debug("RDA: CreateProcessA(), ins_addr=%#x", stored_func.code_loc.ins_addr)
        
        arch = state.arch
        cc = self._calling_convention_resolver.get_cc("CreateProcessA")
        
        # Extract arguments
        arg_app_name = cc.get_next_arg()        # lpApplicationName
        arg_cmd_line = cc.get_next_arg()        # lpCommandLine  
        arg_proc_attr = cc.get_next_arg()       # lpProcessAttributes
        arg_thread_attr = cc.get_next_arg()     # lpThreadAttributes
        arg_inherit = cc.get_next_arg()         # bInheritHandles
        arg_flags = cc.get_next_arg()           # dwCreationFlags
        arg_env = cc.get_next_arg()             # lpEnvironment
        arg_cur_dir = cc.get_next_arg()         # lpCurrentDirectory
        arg_startup = cc.get_next_arg()         # lpStartupInfo
        arg_proc_info = cc.get_next_arg()       # lpProcessInformation
        
        # Get application name and command line (most security-relevant)
        app_name_ptrs = Utils.get_values_from_cc_arg(arg_app_name, state, arch)
        cmd_line_ptrs = Utils.get_values_from_cc_arg(arg_cmd_line, state, arch)
        
        # Resolve strings for application name
        app_names = []
        if not state.is_top(app_name_ptrs.one_value()):
            app_name_strs = Utils.get_strings_from_pointers(app_name_ptrs, state, stored_func.code_loc)
            for app_name in Utils.get_values_from_multivalues(app_name_strs):
                if app_name.concrete:
                    app_names.append(f'"{Utils.bytes_from_int(app_name).decode("latin-1")}"')
                else:
                    app_names.append(f'"{app_name}"')
        
        # Resolve command line
        cmd_lines = []
        if not state.is_top(cmd_line_ptrs.one_value()):
            cmd_line_strs = Utils.get_strings_from_pointers(cmd_line_ptrs, state, stored_func.code_loc)
            for cmd_line in Utils.get_values_from_multivalues(cmd_line_strs):
                if cmd_line.concrete:
                    cmd_lines.append(f'"{Utils.bytes_from_int(cmd_line).decode("latin-1")}"')
                else:
                    cmd_lines.append(f'"{cmd_line}"')
        
        # Create symbolic process handle
        process_name = ' | '.join(app_names) if app_names else ' | '.join(cmd_lines) if cmd_lines else "unknown"
        process_handle = claripy.BVS(
            f"CreateProcessA({process_name})@0x{stored_func.code_loc.ins_addr:x}",
            arch.bits
        )
        process_handle.variables = frozenset(set(process_handle.variables) | {"TOP"})
        
        # Handle PROCESS_INFORMATION output structure
        proc_info_ptrs = Utils.get_values_from_cc_arg(arg_proc_info, state, arch)
        for proc_info_ptr in Utils.get_values_from_multivalues(proc_info_ptrs):
            if not state.is_top(proc_info_ptr):
                # PROCESS_INFORMATION structure (16 bytes on 32-bit, 24 bytes on 64-bit)
                struct_size = 24 if arch.bits == 64 else 16
                memloc = MemoryLocation(proc_info_ptr, struct_size, endness=Endness.LE)
                
                # Create structure data with process/thread handles and IDs
                struct_data = MultiValues(process_handle)
                stored_func.depends(memloc, *stored_func.atoms, value=struct_data)
        
        # Return success (TRUE = 1) or failure (FALSE = 0)
        return_value = MultiValues(claripy.BVV(1, 32))  # Assume success
        return True, state, return_value

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_ReadConsoleA(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        """Handle ReadConsoleA Win32 API call"""
        self.log.debug("RDA: ReadConsoleA(), ins_addr=%#x", stored_func.code_loc.ins_addr)
        
        arch = state.arch
        cc = self._calling_convention_resolver.get_cc("ReadConsoleA")
        
        # Extract arguments (simplified 3-parameter version)
        arg_console = cc.get_next_arg()      # hConsoleInput
        arg_buffer = cc.get_next_arg()       # lpBuffer
        arg_chars_to_read = cc.get_next_arg() # nNumberOfCharsToRead
        
        # Get buffer pointer and size
        buffer_ptrs = Utils.get_values_from_cc_arg(arg_buffer, state, arch)
        chars_to_read = Utils.get_values_from_cc_arg(arg_chars_to_read, state, arch)
        
        # Determine read size
        size_val = Utils.get_concrete_value_from_int(chars_to_read)
        size_val = max(size_val) if size_val is not None else self.MAX_READ_SIZE
        size_val = min(size_val, self.MAX_READ_SIZE)
        
        # Create tainted input data (MATCH GetCommandLineA pattern)
        for buffer_ptr in Utils.get_values_from_multivalues(buffer_ptrs):
            if not state.is_top(buffer_ptr):
                memloc = MemoryLocation(buffer_ptr, size_val, endness=Endness.LE)
                
                # Use same naming pattern as GetCommandLineA
                console_input = claripy.BVS(
                    f"ReadConsoleA(console)@0x{stored_func.code_loc.ins_addr:x}",  # Simplified name
                    size_val * 8
                )
                console_input.variables = frozenset(set(console_input.variables) | {"TOP"})
                
                # Track in fd_tracker (MATCH GetCommandLineA pattern)
                if stored_func.name not in self.fd_tracker:
                    self.fd_tracker[stored_func.name] = []
                
                self.fd_tracker[stored_func.name].append({
                    "val": console_input,
                    "parent": [],  # Simplified like GetCommandLineA
                    "ins_addr": stored_func.code_loc.ins_addr
                })
                
                stored_func.depends(memloc, *stored_func.atoms, value=MultiValues(console_input))
        
        # Return success
        return_value = MultiValues(claripy.BVV(1, 32))
        return True, state, return_value

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_GetCommandLineA(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        """Handle GetCommandLineA Win32 API call"""
        self.log.debug("RDA: GetCommandLineA(), ins_addr=%#x", stored_func.code_loc.ins_addr)
        
        arch = state.arch
        
        # GetCommandLineA has no parameters - it returns a pointer to command line
        # Create symbolic command line data
        cmdline_data = claripy.BVS(
            f"GetCommandLineA(cmdline)@0x{stored_func.code_loc.ins_addr:x}",
            256 * 8  # 256 bytes for command line
        )
        cmdline_data.variables = frozenset(set(cmdline_data.variables) | {"TOP"})
        
        # Track in fd_tracker like other input functions
        if stored_func.name not in self.fd_tracker:
            self.fd_tracker[stored_func.name] = []
        
        self.fd_tracker[stored_func.name].append({
            "val": cmdline_data,
            "parent": [],  # No parent for command line
            "ins_addr": stored_func.code_loc.ins_addr
        })
        
        # Return pointer to command line data
        return_value = MultiValues(cmdline_data)
        return True, state, return_value

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_CreateFileA(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        """Handle CreateFileA Win32 API call"""
        self.log.debug("RDA: CreateFileA(), ins_addr=%#x", stored_func.code_loc.ins_addr)
        
        arch = state.arch
        cc = self._calling_convention_resolver.get_cc("CreateFileA")
        
        # Extract arguments (simplified 3-parameter version)
        arg_filename = cc.get_next_arg()      # lpFileName
        arg_access = cc.get_next_arg()        # dwDesiredAccess
        arg_share = cc.get_next_arg()         # dwShareMode
        
        # Get filename pointer
        filename_ptrs = Utils.get_values_from_cc_arg(arg_filename, state, arch)
        
        # Create file handle representing opened file
        file_handle = claripy.BVS(
            f"CreateFileA(file)@0x{stored_func.code_loc.ins_addr:x}",
            64  # 64-bit handle
        )
        file_handle.variables = frozenset(set(file_handle.variables) | {"TOP"})
        
        # Track in fd_tracker like other input functions
        if stored_func.name not in self.fd_tracker:
            self.fd_tracker[stored_func.name] = []
        
        self.fd_tracker[stored_func.name].append({
            "val": file_handle,
            "parent": [],  # No parent for file handle
            "ins_addr": stored_func.code_loc.ins_addr
        })
        
        # Return file handle
        return_value = MultiValues(file_handle)
        return True, state, return_value

