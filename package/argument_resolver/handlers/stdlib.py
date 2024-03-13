import claripy
from typing import TYPE_CHECKING
import logging

from angr.calling_conventions import SimRegArg, SimStackArg

from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation
from angr.knowledge_plugins.key_definitions.heap_address import HeapAddress
from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions
from angr.knowledge_plugins.key_definitions.tag import ReturnValueTag
from angr.knowledge_plugins.key_definitions.undefined import Undefined

from argument_resolver.formatters.log_formatter import make_logger
from argument_resolver.handlers.base import HandlerBase
from argument_resolver.utils.utils import Utils
from argument_resolver.utils.stored_function import StoredFunction
from argument_resolver.utils.calling_convention import cc_to_rd

from archinfo import Endness


if TYPE_CHECKING:
    from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState


class StdlibHandlers(HandlerBase):
    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_malloc(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        """
        Process the impact of the function's execution on register and memory definitions and uses.
        .. sourcecode:: c
            void *malloc(size_t size);
        :param state:    Register and memory definitions and uses
        :param codeloc:  Code location of the call
        """
        self.log.debug("RDA: malloc(), ins_addr=%#x", stored_func.code_loc.ins_addr)

        cc = self._calling_convention_resolver.get_cc("malloc")

        arg_size = cc.get_next_arg()

        size = Utils.get_values_from_cc_arg(arg_size, state, state.arch)
        size_ints = Utils.get_concrete_value_from_int(size)

        alloc_size = max(size_ints) if size_ints is not None else 0x64
        alloc_size = max(alloc_size, 0x20)
        if size_ints and len(size_ints) >= 2:
            self.log.debug(
                "RDA: malloc(): Found multiple values for size: %s, used %d",
                ", ".join([str(i) for i in size_ints]),
                alloc_size,
            )
        else:
            self.log.debug("RDA: malloc(): No concrete size found")

        heap_addr = state.heap_allocator.allocate(alloc_size)
        memloc = MemoryLocation(heap_addr, alloc_size)
        heap_val = MultiValues(claripy.BVV(0x0, alloc_size*8))
        stored_func.depends(memloc, *stored_func.atoms, value=heap_val)
        ptr = MultiValues(Utils.gen_heap_address(heap_addr.value, state.arch))

        return True, state, ptr

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_calloc(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        """
        Process the impact of the function's execution on register and memory definitions and uses.
        .. sourcecode:: c
            void *calloc(size_t nmemb, size_t size);
        :param state:    Register and memory definitions and uses
        :param codeloc:  Code location of the call
        """
        self.log.debug("RDA: calloc(), ins_addr=%#x", stored_func.code_loc.ins_addr)

        cc = self._calling_convention_resolver.get_cc("calloc")

        arg_nmemb = cc.get_next_arg()
        arg_size = cc.get_next_arg()

        nmemb_values = Utils.get_values_from_cc_arg(arg_nmemb, state, state.arch)
        size_values = Utils.get_values_from_cc_arg(arg_size, state, state.arch)

        nmemb_ints = Utils.get_concrete_value_from_int(nmemb_values)
        size_ints = Utils.get_concrete_value_from_int(size_values)

        nmemb = max(nmemb_ints) if nmemb_ints is not None else 1
        size = max(size_ints) if size_ints is not None else 0x64

        chunk_size = max(nmemb*size, state.arch.bytes*2)
        addr = state.heap_allocator.allocate(chunk_size)
        ptr = claripy.BVV(addr.value, state.arch.bits)
        location = MemoryLocation(addr, chunk_size)

        stored_func.depends(location, *stored_func.atoms, value=MultiValues(claripy.BVV(0, chunk_size*8)))

        return True, state, MultiValues(ptr)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_free(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        """
        Process the impact of the function's execution on register and memory definitions and uses.
        .. sourcecode:: c
            void *free(void *ptr);
        :param state:    Register and memory definitions and uses
        :param codeloc:  Code location of the call
        """
        self.log.debug("RDA: free(), ins_addr=%#x", stored_func.code_loc.ins_addr)

        #cc = self._calling_convention_resolver.get_cc("free")
        #ptr_argument = cc.get_next_arg()

        #ptr_data = Utils.get_values_from_cc_arg(ptr_argument, state, state.arch)

        #for pointer_value in Utils.get_values_from_multivalues(ptr_data):
        #    if Utils.is_heap_address(pointer_value):
        #        heap_offset = Utils.get_heap_offset(pointer_value)
        #        state.heap_allocator.free(HeapAddress(heap_offset))
        #    elif state.is_top(pointer_value):
        #        state.heap_allocator.free(Undefined())
        #    else:
        #        self.log.debug("RDA: free(): Unexpected Pointer Value, got %s", pointer_value)
        return False, state, None

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_rand(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        """
        Process the impact of the function's execution on register and memory definitions and uses.
        .. sourcecode:: c
            int rand(void);
        :param state:    Register and memory definitions and uses
        :param codeloc:  Code location of the call
        """
        self.log.debug("RDA: rand(), ins_addr=%#x", stored_func.code_loc.ins_addr)

        return True, state, MultiValues(claripy.BVV(0xDEADBEEF, state.arch.bits))

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_system(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        """
        Process the impact of the function's execution on register and memory definitions and uses.
        .. sourcecode:: c
            int system(const char *command);
        :param state:    Register and memory definitions and uses
        :param stored_func:  Stored Function data
        """
        self.log.debug("RDA: system(), ins_addr=%#x", stored_func.code_loc.ins_addr)

        # Add definition for return value
        # Let's return 0 by default, assuming everything went fine:
        # > The value returned is -1 on error (e.g., fork(2) failed), and the return status of the command otherwise.

        return True, state, MultiValues(claripy.BVV(0, state.arch.bits))

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_getenv(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        """
        Process the impact of the function's execution on register and memory definitions and uses.
        .. sourcecode:: c
            char *getenv(const char *name);
        :param state:    Register and memory definitions and uses
        :param codeloc:  Code location of the call
        """
        self.log.debug("RDA: getenv(), ins_addr=%#x", stored_func.code_loc.ins_addr)

        arch = state.arch
        cc = self._calling_convention_resolver.get_cc("getenv")

        name_argument = cc.get_next_arg()
        name_pointers = Utils.get_values_from_cc_arg(name_argument, state, arch)
        name_values = Utils.get_strings_from_pointers(name_pointers, state, stored_func.code_loc)


        return_values = MultiValues()
        for offset in name_values.keys():
            for name in name_values[offset]:
                if name.concrete:
                    concrete_name = Utils.bytes_from_int(name).decode("latin-1")
                    buf_bvs = claripy.BVS(f'{stored_func.name}("{concrete_name}")@0x{stored_func.code_loc.ins_addr:x}', self.MAX_READ_SIZE*8)
                    buf_bvs.variables = frozenset(set(buf_bvs.variables) | {"TOP"})
                    self.env_access.add(buf_bvs)
                    ret_val, has_unknown = state.environment.get({concrete_name})
                    if ret_val == {Undefined()}:
                        addr = state.heap_allocator.allocate(self.MAX_READ_SIZE)
                        atom = MemoryLocation(addr, buf_bvs.size()//8, endness=Endness.BE)
                        ret_val = MultiValues(Utils.gen_heap_address(addr.value, state.arch))
                        stored_func.depends(atom, *stored_func.atoms, value=buf_bvs)
                    else:
                        for val in ret_val:
                            atom = MemoryLocation(val, state.arch.bytes)
                            stored_func.depends(atom, *stored_func.atoms)
                        ret_val = MultiValues(offset_to_values={0: ret_val})
                else:
                    addr = state.heap_allocator.allocate(self.MAX_READ_SIZE)
                    buf_bvs = claripy.BVS(f"{stored_func.name}({name})@0x{stored_func.code_loc.ins_addr:x}", self.MAX_READ_SIZE*8)
                    buf_bvs.variables = frozenset(set(buf_bvs.variables) | {"TOP"})
                    atom = MemoryLocation(addr, buf_bvs.size()//8, endness=Endness.BE)
                    ret_val = MultiValues(Utils.gen_heap_address(addr.value, state.arch))
                    stored_func.depends(atom, *stored_func.atoms, value=buf_bvs)
                return_values = return_values.merge(ret_val)

        return True, state, return_values

    def _setenv(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        """
        Process the impact of the function's execution on register and memory definitions and uses.
        .. sourcecode:: c
            int setenv(const char *name, const char *value, int overwrite);
        :param state:    Register and memory definitions and uses
        :param codeloc:  Code location of the call
        """
        self.log.debug("RDA: setenv(), ins_addr=%#x", stored_func.code_loc.ins_addr)

        arch = state.arch
        cc = self._calling_convention_resolver.get_cc(stored_func.name)

        if stored_func.name == "httpSetEnv":
            # discard first arg
            _ = cc.get_next_arg()
        name_argument = cc.get_next_arg()
        value_argument = cc.get_next_arg()

        name_pointers = Utils.get_values_from_cc_arg(name_argument, state, arch)
        name_values = Utils.get_strings_from_pointers(name_pointers, state, stored_func.code_loc)

        value_values = Utils.get_values_from_cc_arg(value_argument, state, arch)

        addrs = set()
        for pointer in Utils.get_values_from_multivalues(value_values):
            strings = Utils.get_strings_from_pointer(pointer, state, stored_func.code_loc)
            size = Utils.get_size_from_multivalue(strings)
            addr = state.heap_allocator.allocate(size)
            addrs.add(Utils.gen_heap_address(addr.value, state.arch))
            atom = MemoryLocation(addr, size, endness=Endness.BE)
            try:
                source_atoms = {defn.atom for defn in LiveDefinitions.extract_defs_from_mv(pointer)}
            except AttributeError:
                source_atoms = {cc_to_rd(value_argument, state.arch, state)}

            stored_func.depends(atom, *source_atoms, value=strings, apply_at_callsite=True)

        for name in Utils.get_values_from_multivalues(name_values):
            if not name.concrete:
                continue

            concrete_name = Utils.bytes_from_int(name).decode("utf-8")
            state.environment.set(concrete_name, addrs)

        return True, state, MultiValues(claripy.BVV(0, state.arch.bits))

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_setenv(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        return self._setenv(state, stored_func)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_httpSetEnv(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        return self._setenv(state, stored_func)
