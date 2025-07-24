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

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_GetEnvironmentVariableA(self, state: ReachingDefinitionsState, stored_func: StoredFunction):
        """Retrieves a handle to the specified standard device 
        (standard input, standard output, or standard error).
        C++
            DWORD GetEnvironmentVariableA(
            [in, optional]  LPCSTR lpName,
            [out, optional] LPSTR  lpBuffer,
            [in]            DWORD  nSize
            );
            
        :param stored_func:
        :param state: Register and memory definitions and uses
        """
        self.log.debug("RDA: GetEnvironmentVariableA, ins_addr=%#x", stored_func.code_loc.ins_addr)

        arch = state.arch
        cc = self._calling_convention_resolver.get_cc("GetEnvironmentVariableA")
        
        env_name = cc.get_next_arg()            #lpName
        str_buffer = cc.get_next_arg()          #lpBuffer
        str_buffer_size = cc.get_next_arg()     #nSize
        
        env_name_ptr = Utils.get_values_from_cc_arg(env_name, state, arch)
        str_buffer_ptr = Utils.get_values_from_cc_arg(str_buffer, state, arch)
        size_values = Utils.get_values_from_cc_arg(str_buffer_size, state, arch)
        
    
        # Step 3c: Create symbolic data (for sources)
        env_bvs = claripy.BVS(
            f"{stored_func.name}(env_var)@0x{stored_func.code_loc.ins_addr:x}",
            256 * 8  # 256 bytes for environment variable
        )
        env_bvs.variables = frozenset(set(env_bvs.variables) | {"TOP"})
        
        # Step 3d: Track in fd_tracker (for sources)
        if stored_func.name not in self.fd_tracker:
            self.fd_tracker[stored_func.name] = []
        
        self.fd_tracker[stored_func.name].append({
            "val": env_bvs,
            "parent": [],
            "ins_addr": stored_func.code_loc.ins_addr
        })
        
        # Step 3e: Create memory dependencies for buffer
        for ptr in Utils.get_values_from_multivalues(str_buffer_ptr):
            for size_val in Utils.get_values_from_multivalues(size_values):
                sp_offset = SpOffset(arch.bits, state.get_stack_offset(ptr))
                if sp_offset.offset is not None:
                    if size_val.concrete:
                        size = min(size_val.concrete_value, self.MAX_READ_SIZE)
                        memloc = MemoryLocation(sp_offset, size, endness=Endness.BE)
                    else:
                        memloc = MemoryLocation(sp_offset, arch.bytes, endness=Endness.BE)
                    
                    # Create dependency
                    mv = MultiValues(env_bvs)
                    stored_func.depends(memloc, *stored_func.atoms, value=mv)
        
        # Step 3f: Return success with symbolic return value
        return_val = claripy.BVV(len("dummy_env_value"), 32)  # Simulate string length
        return True, state, MultiValues(return_val)
    
   
    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_lstrcpyA(self, state: ReachingDefinitionsState, stored_func: StoredFunction):
        """
        Handle lstrcpyA - Windows string copy with taint propagation
        C++
        LPSTR lstrcpyA(
            [out] LPSTR  lpString1,
            [in]  LPCSTR lpString2
            );
        :param stored_func: Function call information and location
        :param state: Register and memory definitions and uses
        """
        self.log.debug("RDA: lstrcpyA, ins_addr=%#x", stored_func.code_loc.ins_addr)
        
        arch = state.arch
        cc = self._calling_convention_resolver.get_cc("lstrcpyA")
        
        # Extract parameters
        dest_arg = cc.get_next_arg()
        src_arg = cc.get_next_arg()
        
        # Get parameter values
        dest_ptrs = Utils.get_values_from_cc_arg(dest_arg, state, arch)
        src_ptrs = Utils.get_values_from_cc_arg(src_arg, state, arch)
        
        # Create symbolic data for string copy (assume taint propagation)
        for dest_ptr in Utils.get_values_from_multivalues(dest_ptrs):
            sp_offset = SpOffset(arch.bits, state.get_stack_offset(dest_ptr))
            if sp_offset.offset is None:
                continue
            
            # Create memory location for destination string
            memloc = MemoryLocation(sp_offset, 256, endness=Endness.BE)
            
            # Create symbolic string data (preserves taint)
            string_bvs = claripy.BVS(
                f"{stored_func.name}(copied_string)@0x{stored_func.code_loc.ins_addr:x}",
                memloc.size * 8
            )
            string_bvs.variables = frozenset(set(string_bvs.variables) | {"TOP"})
            
            # Create memory dependency
            mv = MultiValues(string_bvs)
            stored_func.depends(memloc, *stored_func.atoms, value=mv)
        
        # Track string operation
        if stored_func.name not in self.fd_tracker:
            self.fd_tracker[stored_func.name] = []
        
        self.fd_tracker[stored_func.name].append({
            "val": string_bvs,
            "parent": [],
            "ins_addr": stored_func.code_loc.ins_addr
        })
        
        self.log.debug("lstrcpyA: String copy operation tracked")
        
        # Return destination pointer
        return True, state, dest_ptrs

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_GetStdHandle(self, state: ReachingDefinitionsState, stored_func: StoredFunction):
        """
        Handle GetStdHandle - Returns standard device handles
        C++
        HANDLE WINAPI GetStdHandle(
                _In_ DWORD nStdHandle
                );
        .. sourcecode:: c
            HANDLE GetStdHandle(DWORD nStdHandle);
        :param stored_func: Function call information and location
        :param state: Register and memory definitions and uses
        """
        self.log.debug("RDA: GetStdHandle, ins_addr=%#x", stored_func.code_loc.ins_addr)
        arch = state.arch
        cc = self._calling_convention_resolver.get_cc("GetStdHandle")
    
        # Extract nStdHandle parameter
        std_handle_arg = cc.get_next_arg()
        std_handle_values = Utils.get_values_from_cc_arg(std_handle_arg, state, arch)
        
        # Create handle based on standard device type
        handle_bvs = claripy.BVS(
            f"{stored_func.name}(std_handle)@0x{stored_func.code_loc.ins_addr:x}",
            arch.bits
        )
        handle_bvs.variables = frozenset(set(handle_bvs.variables) | {"TOP"})
        
        # Store in fd_tracker for future I/O operations
        if stored_func.name not in self.fd_tracker:
            self.fd_tracker[stored_func.name] = []
        
        # Determine handle type based on nStdHandle value
        handle_type = "unknown"
        for std_val in Utils.get_values_from_multivalues(std_handle_values):
            if std_val.concrete:
                if std_val.concrete_value == 0xFFFFFFF6:  # STD_INPUT_HANDLE (-10)
                    handle_type = "stdin"
                elif std_val.concrete_value == 0xFFFFFFF5:  # STD_OUTPUT_HANDLE (-11)
                    handle_type = "stdout"
                elif std_val.concrete_value == 0xFFFFFFF4:  # STD_ERROR_HANDLE (-12)
                    handle_type = "stderr"
        
        # Update handle name with type information
        if handle_type != "unknown":
            handle_bvs = claripy.BVS(
                f"{stored_func.name}({handle_type})@0x{stored_func.code_loc.ins_addr:x}",
                arch.bits
            )
            handle_bvs.variables = frozenset(set(handle_bvs.variables) | {"TOP"})
        
        self.fd_tracker[stored_func.name].append({
            "val": handle_bvs,
            "parent": [],
            "ins_addr": stored_func.code_loc.ins_addr,
            "handle_type": handle_type
        })
        
        return True, state, MultiValues(handle_bvs)
    
    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_lstrcatA(self, state: ReachingDefinitionsState, stored_func: StoredFunction):
        """
        Handle lstrcatA - Windows string concatenation with taint propagation
        C++
        LPSTR lstrcatA(
            [in, out] LPSTR  lpString1,
            [in]      LPCSTR lpString2
            );
        :param stored_func: Function call information and location
        :param state: Register and memory definitions and uses
        """
        self.log.debug("RDA: lstrcatA, ins_addr=%#x", stored_func.code_loc.ins_addr)
        
        arch = state.arch
        cc = self._calling_convention_resolver.get_cc("lstrcatA")
        
        # Extract parameters
        dest_arg = cc.get_next_arg()        # lpString1 (destination)
        src_arg = cc.get_next_arg()         # lpString2 (source to append)
        
        # Get parameter values
        dest_ptrs = Utils.get_values_from_cc_arg(dest_arg, state, arch)
        src_ptrs = Utils.get_values_from_cc_arg(src_arg, state, arch)
        
        # Create symbolic data for string concatenation (preserves taint from both strings)
        for dest_ptr in Utils.get_values_from_multivalues(dest_ptrs):
            sp_offset = SpOffset(arch.bits, state.get_stack_offset(dest_ptr))
            if sp_offset.offset is None:
                continue
            
            # Create memory location for destination string (larger size for concatenation)
            memloc = MemoryLocation(sp_offset, 512, endness=Endness.BE)  # Larger for concat
            
            # Create symbolic string data (represents concatenated result)
            concat_bvs = claripy.BVS(
                f"{stored_func.name}(concatenated_string)@0x{stored_func.code_loc.ins_addr:x}",
                memloc.size * 8
            )
            concat_bvs.variables = frozenset(set(concat_bvs.variables) | {"TOP"})
            
            # Create memory dependency for concatenated result
            mv = MultiValues(concat_bvs)
            stored_func.depends(memloc, *stored_func.atoms, value=mv)
        
        # Track string concatenation operation
        if stored_func.name not in self.fd_tracker:
            self.fd_tracker[stored_func.name] = []
        
        self.fd_tracker[stored_func.name].append({
            "val": concat_bvs,
            "parent": [],
            "ins_addr": stored_func.code_loc.ins_addr,
            "operation": "string_concatenation"
        })
        
        self.log.debug("lstrcatA: String concatenation operation tracked")
        
        # Return destination pointer (lstrcat returns lpString1)
        return True, state, dest_ptrs
    
    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_HeapFree(self, state: ReachingDefinitionsState, stored_func: StoredFunction):
        """
        Handle HeapFree - Cleans up heap memory allocation tracking
        C++
            BOOL HeapFree(
            [in] HANDLE                 hHeap,
            [in] DWORD                  dwFlags,
            [in] _Frees_ptr_opt_ LPVOID lpMem
            );
        :param stored_func: Function call information and location
        :param state: Register and memory definitions and uses
        """
        self.log.debug("RDA: HeapFree, ins_addr=%#x", stored_func.code_loc.ins_addr)
        
        arch = state.arch
        cc = self._calling_convention_resolver.get_cc("HeapFree")
        
        # Extract parameters
        heap_arg = cc.get_next_arg()
        flags_arg = cc.get_next_arg()
        mem_arg = cc.get_next_arg()
        
        # Get memory pointer for tracking
        mem_values = Utils.get_values_from_cc_arg(mem_arg, state, arch)
        
        # Create marker for this free operation
        free_marker = claripy.BVS(
            f"{stored_func.name}(memory_freed)@0x{stored_func.code_loc.ins_addr:x}",
            arch.bits
        )
        
        # Track the free operation (for debugging and preventing double-free detection)
        if stored_func.name not in self.fd_tracker:
            self.fd_tracker[stored_func.name] = []
        
        self.fd_tracker[stored_func.name].append({
            "val": free_marker,
            "parent": [],
            "ins_addr": stored_func.code_loc.ins_addr,
            "action": "memory_freed"
        })
        
        self.log.debug("HeapFree: Marked memory as freed")
        
        # Return success (TRUE)
        return_val = claripy.BVV(1, 32)
        return True, state, MultiValues(return_val)
        
    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_LocalAlloc(self, state: ReachingDefinitionsState, stored_func: StoredFunction):
        """
        Handle LocalAlloc - Windows local memory allocation
        .. sourcecode:: c
            HLOCAL LocalAlloc(UINT uFlags, SIZE_T uBytes);
        :param stored_func: Function call information and location
        :param state: Register and memory definitions and uses
        """
        self.log.debug("RDA: LocalAlloc, ins_addr=%#x", stored_func.code_loc.ins_addr)
        
        arch = state.arch
        cc = self._calling_convention_resolver.get_cc("LocalAlloc")
        
        # Extract parameters
        flags_arg = cc.get_next_arg()        # uFlags
        size_arg = cc.get_next_arg()         # uBytes
        
        # Get parameter values
        flags_vals = Utils.get_values_from_cc_arg(flags_arg, state, arch)
        size_vals = Utils.get_values_from_cc_arg(size_arg, state, arch)
        
        # Create symbolic memory handle for allocated local memory
        allocated_handle = claripy.BVS(
            f"{stored_func.name}(local_memory)@0x{stored_func.code_loc.ins_addr:x}",
            arch.bits  # Handle size (64-bit on x64)
        )
        
        # Track the allocation in fd_tracker
        if stored_func.name not in self.fd_tracker:
            self.fd_tracker[stored_func.name] = []
        
        # Determine allocation size for tracking
        allocation_size = 512  # Default size for local allocations
        for size_val in Utils.get_values_from_multivalues(size_vals):
            if size_val.concrete:
                allocation_size = size_val.concrete_value
                break
        
        # Store allocation information
        self.fd_tracker[stored_func.name].append({
            "val": allocated_handle,
            "parent": [],
            "ins_addr": stored_func.code_loc.ins_addr,
            "size": allocation_size,
            "type": "local_memory"
        })
        
        # Log allocation flags for security analysis
        for flags_val in Utils.get_values_from_multivalues(flags_vals):
            if flags_val.concrete:
                flags = flags_val.concrete_value
                if flags & 0x0040:  # LMEM_ZEROINIT
                    self.log.debug("LocalAlloc: Zero-initialized memory at %#x", 
                                stored_func.code_loc.ins_addr)
                if flags & 0x0002:  # LMEM_MOVEABLE
                    self.log.debug("LocalAlloc: Moveable memory at %#x", 
                                stored_func.code_loc.ins_addr)
                if flags & 0x0000:  # LMEM_FIXED
                    self.log.debug("LocalAlloc: Fixed memory at %#x", 
                                stored_func.code_loc.ins_addr)
        
        return True, state, MultiValues(allocated_handle)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_LocalFree(self, state: ReachingDefinitionsState, stored_func: StoredFunction):
        """
        Handle LocalFree - Windows local memory deallocation
        .. sourcecode:: c
            HLOCAL LocalFree(HLOCAL hMem);
        :param stored_func: Function call information and location
        :param state: Register and memory definitions and uses
        """
        self.log.debug("RDA: LocalFree, ins_addr=%#x", stored_func.code_loc.ins_addr)
        
        arch = state.arch
        cc = self._calling_convention_resolver.get_cc("LocalFree")
        
        # Extract parameter
        handle_arg = cc.get_next_arg()       # hMem
        handle_vals = Utils.get_values_from_cc_arg(handle_arg, state, arch)
        
        # Clean up tracking for freed local memory
        for handle_val in Utils.get_values_from_multivalues(handle_vals):
            if handle_val.concrete:
                freed_handle = handle_val.concrete_value
                self.log.debug("LocalFree: Local memory freed at handle %#x", freed_handle)
            elif hasattr(handle_val, 'depends') and handle_val.depends():
                # Track symbolic handle dependencies
                self.log.debug("LocalFree: Symbolic local memory freed at %#x", 
                            stored_func.code_loc.ins_addr)
        
        # Return NULL on success (standard LocalFree behavior)
        success_val = claripy.BVV(0, arch.bits)  # NULL pointer
        return True, state, MultiValues(success_val)

        
            

        
            

    
    
    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_CloseHandle(self, state: ReachingDefinitionsState, stored_func: StoredFunction):
        """
        Handle CloseHandle - Closes handles and cleans up tracking
        
        C++
            BOOL CloseHandle(
            [in] HANDLE hObject
            );
            
        :param stored_func: Function call information and location
        :param state: Register and memory definitions and uses
        """
        self.log.debug("RDA: CloseHandle, ins_addr=%#x", stored_func.code_loc.ins_addr)
        
        arch = state.arch
        cc = self._calling_convention_resolver.get_cc("CloseHandle")
        
        # Extract handle parameter
        handle_arg = cc.get_next_arg()
        handle_values = Utils.get_values_from_cc_arg(handle_arg, state, arch)
        
        # Attempt to find and remove handle from fd_tracker
        handles_closed = 0
        for handle_val in Utils.get_values_from_multivalues(handle_values):
            # Search through fd_tracker for matching handles
            for func_name, handle_list in self.fd_tracker.items():
                if isinstance(handle_list, list):
                    # Look for handles that match this value
                    for i, handle_entry in enumerate(handle_list):
                        if isinstance(handle_entry, dict) and "val" in handle_entry:
                            handle_bvs = handle_entry["val"]
                            # Check if this handle matches (simplified comparison)
                            if hasattr(handle_bvs, 'variables') and "TOP" in handle_bvs.variables:
                                # Remove this handle entry
                                self.log.debug("CloseHandle: Removing handle from %s", func_name)
                                handle_list.pop(i)
                                handles_closed += 1
                                break
        
        # Also clean up any integer-keyed handles (like stdin/stdout/stderr)
        for fd_key in list(self.fd_tracker.keys()):
            if isinstance(fd_key, int):
                # Check if this handle value matches any standard handles
                for handle_val in Utils.get_values_from_multivalues(handle_values):
                    if handle_val.concrete and handle_val.concrete_value == fd_key:
                        self.log.debug("CloseHandle: Removing standard handle %d", fd_key)
                        del self.fd_tracker[fd_key]
                        handles_closed += 1
                        break
        
        # Log cleanup results
        if handles_closed > 0:
            self.log.debug("CloseHandle: Successfully closed %d handles", handles_closed)
        else:
            self.log.debug("CloseHandle: No matching handles found in fd_tracker")
        
        # Return success (TRUE)
        return_val = claripy.BVV(1, 32)  # TRUE
        return True, state, MultiValues(return_val)

        
            
        
    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_GlobalAlloc(self, state: ReachingDefinitionsState, stored_func: StoredFunction):
        """
        Handle GlobalAlloc - Windows global memory allocation
        .. sourcecode:: c
            HGLOBAL GlobalAlloc(UINT uFlags, SIZE_T dwBytes);
        :param stored_func: Function call information and location
        :param state: Register and memory definitions and uses
        """
        self.log.debug("RDA: GlobalAlloc, ins_addr=%#x", stored_func.code_loc.ins_addr)
        
        arch = state.arch
        cc = self._calling_convention_resolver.get_cc("GlobalAlloc")
        
        # Extract parameters
        flags_arg = cc.get_next_arg()        # uFlags
        size_arg = cc.get_next_arg()         # dwBytes
        
        # Get parameter values
        flags_vals = Utils.get_values_from_cc_arg(flags_arg, state, arch)
        size_vals = Utils.get_values_from_cc_arg(size_arg, state, arch)
        
        # Create symbolic memory handle for allocated memory
        allocated_handle = claripy.BVS(
            f"{stored_func.name}(global_memory)@0x{stored_func.code_loc.ins_addr:x}",
            arch.bits  # Handle size (64-bit on x64)
        )
        
        # Track the allocation in fd_tracker
        if stored_func.name not in self.fd_tracker:
            self.fd_tracker[stored_func.name] = []
        
        # Determine allocation size for tracking
        allocation_size = 1024  # Default size
        for size_val in Utils.get_values_from_multivalues(size_vals):
            if size_val.concrete:
                allocation_size = size_val.concrete_value
                break
        
        # Store allocation information
        self.fd_tracker[stored_func.name].append({
            "val": allocated_handle,
            "parent": [],
            "ins_addr": stored_func.code_loc.ins_addr,
            "size": allocation_size,
            "type": "global_memory"
        })
        
        # Log allocation flags for security analysis
        for flags_val in Utils.get_values_from_multivalues(flags_vals):
            if flags_val.concrete:
                flags = flags_val.concrete_value
                if flags & 0x0040:  # GMEM_ZEROINIT
                    self.log.debug("GlobalAlloc: Zero-initialized memory at %#x", 
                                stored_func.code_loc.ins_addr)
                if flags & 0x0002:  # GMEM_MOVEABLE
                    self.log.debug("GlobalAlloc: Moveable memory at %#x", 
                                stored_func.code_loc.ins_addr)
        
        return True, state, MultiValues(allocated_handle)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_GlobalFree(self, state: ReachingDefinitionsState, stored_func: StoredFunction):
        """
        Handle GlobalFree - Windows global memory deallocation
        .. sourcecode:: c
            HGLOBAL GlobalFree(HGLOBAL hMem);
        :param stored_func: Function call information and location
        :param state: Register and memory definitions and uses
        """
        self.log.debug("RDA: GlobalFree, ins_addr=%#x", stored_func.code_loc.ins_addr)
        
        arch = state.arch
        cc = self._calling_convention_resolver.get_cc("GlobalFree")
        
        # Extract parameter
        handle_arg = cc.get_next_arg()       # hMem
        handle_vals = Utils.get_values_from_cc_arg(handle_arg, state, arch)
        
        # Clean up tracking for freed memory
        for handle_val in Utils.get_values_from_multivalues(handle_vals):
            if handle_val.concrete:
                freed_handle = handle_val.concrete_value
                self.log.debug("GlobalFree: Memory freed at handle %#x", freed_handle)
        
        # Return NULL on success (standard GlobalFree behavior)
        success_val = claripy.BVV(0, arch.bits)  # NULL pointer
        return True, state, MultiValues(success_val)


    def handle_HeapAlloc(self, state: ReachingDefinitionsState, stored_func: StoredFunction):
        """
        Handle HeapAlloc - Tracks dynamic memory allocation
        C++
            DECLSPEC_ALLOCATOR LPVOID HeapAlloc(
            [in] HANDLE hHeap,
            [in] DWORD  dwFlags,
            [in] SIZE_T dwBytes
            );
        :param stored_func: Function call information and location
        :param state: Register and memory definitions and uses
        """
        self.log.debug("RDA: HeapAlloc, ins_addr=%#x", stored_func.code_loc.ins_addr)
        
        arch = state.arch
        cc = self._calling_convention_resolver.get_cc("HeapAlloc")
        
        # Extract parameters
        heap_arg = cc.get_next_arg()
        flags_arg = cc.get_next_arg()
        size_arg = cc.get_next_arg()
        
        # Create symbolic pointer for allocated memory
        alloc_ptr = claripy.BVS(
            f"{stored_func.name}(heap_memory)@0x{stored_func.code_loc.ins_addr:x}",
            arch.bits
        )
        alloc_ptr.variables = frozenset(set(alloc_ptr.variables) | {"TOP"})
        
        # Store in fd_tracker using function name (like other handlers)
        if stored_func.name not in self.fd_tracker:
            self.fd_tracker[stored_func.name] = []
        
        self.fd_tracker[stored_func.name].append({
            "val": alloc_ptr,
            "parent": [],
            "ins_addr": stored_func.code_loc.ins_addr
        })
        
        return True, state, MultiValues(alloc_ptr)
            
    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_lstrlenA(self, state: ReachingDefinitionsState, stored_func: StoredFunction):
        """
        Handle lstrlenA - Windows string length calculation
        .. sourcecode:: c
            int lstrlenA(LPCSTR lpString);
        :param stored_func: Function call information and location
        :param state: Register and memory definitions and uses
        """
        self.log.debug("RDA: lstrlenA, ins_addr=%#x", stored_func.code_loc.ins_addr)
        
        arch = state.arch
        cc = self._calling_convention_resolver.get_cc("lstrlenA")
        
        # Extract parameter (for calling convention compliance)
        string_arg = cc.get_next_arg()
        string_ptrs = Utils.get_values_from_cc_arg(string_arg, state, arch)
        
        # Return concrete length - no fd_tracker needed for length operations
        length_val = claripy.BVV(32, 32)  # Assume 32-character string
        return True, state, MultiValues(length_val)
    
    
        
    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_VirtualAlloc(self, state: ReachingDefinitionsState, stored_func: StoredFunction):
        """
        Handle VirtualAlloc - Windows virtual memory allocation
        .. sourcecode:: c
            LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
        :param stored_func: Function call information and location
        :param state: Register and memory definitions and uses
        """
        self.log.debug("RDA: VirtualAlloc, ins_addr=%#x", stored_func.code_loc.ins_addr)
        
        arch = state.arch
        cc = self._calling_convention_resolver.get_cc("VirtualAlloc")
        
        # Extract parameters
        address_arg = cc.get_next_arg()      # lpAddress
        size_arg = cc.get_next_arg()         # dwSize
        alloc_type_arg = cc.get_next_arg()   # flAllocationType
        protect_arg = cc.get_next_arg()      # flProtect
        
        # Get parameter values
        address_vals = Utils.get_values_from_cc_arg(address_arg, state, arch)
        size_vals = Utils.get_values_from_cc_arg(size_arg, state, arch)
        protect_vals = Utils.get_values_from_cc_arg(protect_arg, state, arch)
        
        # Create symbolic memory pointer for allocated memory
        allocated_ptr = claripy.BVS(
            f"{stored_func.name}(allocated_memory)@0x{stored_func.code_loc.ins_addr:x}",
            arch.bits  # Pointer size (64-bit on x64)
        )
        
        # Track the allocation in fd_tracker
        if stored_func.name not in self.fd_tracker:
            self.fd_tracker[stored_func.name] = []
        
        # Determine allocation size for tracking
        allocation_size = 4096  # Default page size
        for size_val in Utils.get_values_from_multivalues(size_vals):
            if size_val.concrete:
                allocation_size = size_val.concrete_value
                break
        
        # Store allocation information
        self.fd_tracker[stored_func.name].append({
            "val": allocated_ptr,
            "parent": [],
            "ins_addr": stored_func.code_loc.ins_addr,
            "size": allocation_size,
            "type": "virtual_memory"
        })
        
        # Log security-relevant information
        for protect_val in Utils.get_values_from_multivalues(protect_vals):
            if protect_val.concrete:
                protect_flags = protect_val.concrete_value
                # Check for executable memory (PAGE_EXECUTE_* flags)
                if protect_flags & 0x10:  # PAGE_EXECUTE
                    self.log.warning("VirtualAlloc: Executable memory allocated at %#x", 
                                stored_func.code_loc.ins_addr)
                if protect_flags & 0x40:  # PAGE_EXECUTE_READWRITE
                    self.log.warning("VirtualAlloc: RWX memory allocated at %#x", 
                                stored_func.code_loc.ins_addr)
        
        return True, state, MultiValues(allocated_ptr)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_VirtualFree(self, state: ReachingDefinitionsState, stored_func: StoredFunction):
        """
        Handle VirtualFree - Windows virtual memory deallocation
        .. sourcecode:: c
            BOOL VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
        :param stored_func: Function call information and location
        :param state: Register and memory definitions and uses
        """
        self.log.debug("RDA: VirtualFree, ins_addr=%#x", stored_func.code_loc.ins_addr)
        
        arch = state.arch
        cc = self._calling_convention_resolver.get_cc("VirtualFree")
        
        # Extract parameters
        address_arg = cc.get_next_arg()      # lpAddress
        size_arg = cc.get_next_arg()         # dwSize
        free_type_arg = cc.get_next_arg()    # dwFreeType
        
        address_vals = Utils.get_values_from_cc_arg(address_arg, state, arch)
        
        # Clean up tracking for freed memory
        for address_val in Utils.get_values_from_multivalues(address_vals):
            if address_val.concrete:
                freed_addr = address_val.concrete_value
                self.log.debug("VirtualFree: Memory freed at address %#x", freed_addr)
        
        # Return success (TRUE)
        success_val = claripy.BVV(1, 32)  # BOOL TRUE
        return True, state, MultiValues(success_val)
