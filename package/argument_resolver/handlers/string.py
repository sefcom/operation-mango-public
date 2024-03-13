import logging

import claripy
import itertools
import functools
import re

from typing import Optional, Tuple

from angr.calling_conventions import SimRegArg, SimStackArg
from angr.knowledge_plugins.key_definitions.atoms import (
    MemoryLocation,
    SpOffset,
    Register,
)

from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from angr.knowledge_plugins.key_definitions.tag import (
    SideEffectTag,
    ReturnValueTag,
)
from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions, DerefSize
from angr.knowledge_plugins.key_definitions.heap_address import HeapAddress
from angr.errors import SimMemoryError

from argument_resolver.formatters.log_formatter import make_logger
from argument_resolver.handlers.base import HandlerBase
from argument_resolver.utils.calling_convention import cc_to_rd
from argument_resolver.utils.utils import Utils
from argument_resolver.utils.stored_function import StoredFunction

from archinfo import Endness


class StringHandlers(HandlerBase):
    """
    Handlers for <string.h>'s functions
        strcmp, strncmp, strncmp, strncasecmp, strcoll, strcpy, strncpy, strcat, strncat
    *NOTE*: Please think twice before adding class attributes:
            It should happen *ONLY* for `string.h` functions that have an internal state that the analysis needs to model.
    """

    # As per the documentation:
    #   "On the first call to strtok() the string to be parsed should be specified in str.
    #    In each subsequent call that should parse the same string, str should be NULL."
    _strtok_remaining_string_pointers: Optional[MultiValues] = None

    def _handle_strcat(
        self,
        state: "ReachingDefinitionsState",
        stored_func: StoredFunction,
    ):
        """
        :param LiveDefinitions state:        Register and memory definitions and uses
        :param Codeloc codeloc:              Code location of the call
        :param str handler_name:             Name of the handler
        """
        self.log.debug("RDA: %s(), ins_addr=%#x", stored_func.name, stored_func.code_loc.ins_addr)

        cc = self._calling_convention_resolver.get_cc(stored_func.name)
        # Get sim function arguments
        arg_dst = cc.get_next_arg()
        arg_src = cc.get_next_arg()

        # Extract pointers for arguments
        dst_ptrs = Utils.get_values_from_cc_arg(arg_dst, state, state.arch)
        src_ptrs = Utils.get_values_from_cc_arg(arg_src, state, state.arch)

        # Evaluate all pointers

        dst_values = []
        for dst_atom in state.deref(dst_ptrs, DerefSize.NULL_TERMINATE):
            dst_strings = state.get_values(dst_atom)
            if dst_strings is None:
                dst_values.append((MultiValues(state.top(state.arch.bits)), dst_atom))
                continue

            new_dst_strings = MultiValues()
            for dst_string in dst_strings[0]:
                if dst_string.size() >= 8:
                    last_byte = dst_string.get_byte(dst_string.size() // 8 - 1)
                    if last_byte.concrete and last_byte.concrete_value == 0:
                        dst_string = dst_string.get_bytes(0, dst_string.size() // 8 - 1)
                if dst_string.size() == 0:
                    dst_string = state.top(state.arch.bits)
                new_dst_strings.add_value(0, dst_string)
            dst_values.append((new_dst_strings, dst_atom))

        src_values = []
        for src_atom in state.deref(src_ptrs, DerefSize.NULL_TERMINATE):
            if src_atom.size == 4096:
                src_strings = MultiValues(state.top(state.arch.bits))
            else:
                src_strings = state.get_values(src_atom)
                if src_strings is None:
                    src_strings = MultiValues(state.top(state.arch.bits))

            src_values.append((src_strings, src_atom))

        if len(dst_values) == 0:
            dst_values.append((MultiValues(state.top(state.arch.bits)), None))
        elif len(src_values) == 0:
            src_values.append((MultiValues(state.top(state.arch.bits)), None))

        for d, s in itertools.product(dst_values, src_values):
            d_val, d_atom = d
            s_val, s_atom = s
            if d_atom is None:
                continue

            concat_value = d_val.concat(s_val)
            dst_memloc = MemoryLocation(d_atom.addr, Utils.get_size_from_multivalue(concat_value), endness=Endness.BE)
            atoms = [d_atom]
            if s_atom is not None:
                atoms.append(s_atom)
            stored_func.depends(dst_memloc, *atoms, value=concat_value)

        return True, state, dst_ptrs

    def _handle_strcmp(
        self,
        state: "ReachingDefinitionsState",
        stored_func: StoredFunction,
        ignore_case: bool = True,
    ):
        """
        :param LiveDefinitions state::       Register and memory definitions and uses
        :param Codeloc codeloc:              Code location of the call
        :param str handler_name:             Name of the handler
        :param bool ignore_case:             Case sensitivity
        """
        self.log.debug("RDA: %s(), ins_addr=%#x", stored_func.name, stored_func.code_loc.ins_addr)

        res = MultiValues(
            offset_to_values={
                0: {
                    claripy.BVV(-1, state.arch.bits),
                    claripy.BVV(0, state.arch.bits),
                    claripy.BVV(1, state.arch.bits),
                }
            }
        )

        return True, state, res

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_strcmp(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        """
        Process the impact of the function's execution on register and memory definitions and uses.
        .. sourcecode:: c
            int strcmp ( const char * str1, const char * str2 );
        """
        return self._handle_strcmp(state, stored_func, ignore_case=True)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_strncmp(
        self, state: "ReachingDefinitionsState", stored_func: StoredFunction
    ):
        """
        .. sourcecode:: c
            int strncmp(const char *s1, const char *s2, size_t n);
        """
        self.log.debug("RDA: strncmp(): Using strcmp(). Size n is ignored.")
        return self._handle_strcmp(state, stored_func, ignore_case=True)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_strcasecmp(
        self, state: "ReachingDefinitionsState", stored_func: StoredFunction
    ):
        """
        .. sourcecode:: c
            int strcasecmp(const char *s1, const char *s2);
        """
        return self._handle_strcmp(state, stored_func, ignore_case=False)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_strncasecmp(
        self, state: "ReachingDefinitionsState", stored_func: StoredFunction
    ):
        """
        .. sourcecode:: c
            int strncasecmp(const char *s1, const char *s2, size_t n);
        """
        self.log.debug(
            "RDA: strncasecmp(): Using strcmp() case sensitivity. Size n is ignored."
        )
        return self._handle_strcmp(state, stored_func, ignore_case=False)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_strcoll(
        self, state: "ReachingDefinitionsState", stored_func: StoredFunction
    ):
        """
        .. sourcecode:: c
            int strcoll(const char *s1, const char *s2);
        """
        self.log.debug("RDA: strcoll(): Using strcmp(). Locales are ignored.")
        return self._handle_strcmp(state, stored_func, ignore_case=True)

    def _handle_strcpy(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        cc = self._calling_convention_resolver.get_cc("strcpy")
        # Get sim function arguments
        arg_dst = cc.get_next_arg()
        arg_src = cc.get_next_arg()

        # Extract values for arguments
        dst_ptrs = Utils.get_values_from_cc_arg(arg_dst, state, state.arch)
        src_ptrs = Utils.get_values_from_cc_arg(arg_src, state, state.arch)

        # Evaluate all pointers
        for dst_ptr in Utils.get_values_from_multivalues(dst_ptrs):
            if state.is_top(dst_ptr):
                self.log.debug("RDA: strcpy(): Destination pointer undefined")
            elif state.is_stack_address(dst_ptr) or state.is_heap_address(dst_ptr):
                src_values = Utils.get_strings_from_pointers(
                    src_ptrs, state, stored_func.code_loc
                )
                max_size = Utils.get_size_from_multivalue(src_values)
                if max_size == 0:
                    max_size = state.arch.bytes
                    src_values = MultiValues(state.top(state.arch.bits))
                if state.is_heap_address(dst_ptr):
                    heap_offset = state.get_heap_offset(dst_ptr)
                    sub_atom = HeapAddress(heap_offset)
                else:
                    sub_atom = dst_ptr
                    #stack_offset = state.get_stack_offset(dst_ptr)
                    #sub_atom = SpOffset(state.arch.bits, stack_offset)
                memloc = MemoryLocation(sub_atom, max_size, endness=Endness.BE)
                src_memlocs = {MemoryLocation(src_ptr, max_size) for src_ptr in
                               Utils.get_values_from_multivalues(src_ptrs)}
                stored_func.depends(memloc, *src_memlocs, value=src_values)
            else:
                self.log.debug(
                    "RDA: strcpy(): Expected TOP or stack offset, got %s",
                    type(dst_ptr).__name__,
                )

        return True, state, dst_ptrs

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_strcpy(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        """
        Process the impact of the function's execution on register and memory definitions and uses.
        .. sourcecode:: c
            char *strcpy (char * dst, const char * src);
        """
        self.log.debug("RDA: strcpy(), ins_addr=%#x", stored_func.code_loc.ins_addr)
        return self._handle_strcpy(state, stored_func)


    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_strncpy(
        self, state: "ReachingDefinitionsState", stored_func: StoredFunction
    ):
        """
        .. sourcecode:: c
            char *strncpy(char *dst, const char *src, size_t n);
        """
        self.log.debug("RDA: strncpy(), ins_addr=%#x", stored_func.code_loc.ins_addr)
        # GDI just use regular strcpy
        return self._handle_strcpy(state, stored_func)

        #cc = self._calling_convention_resolver.get_cc("strncpy")

        #dst_argument = cc.get_next_arg()
        #src_argument = cc.get_next_arg()
        #n_argument = cc.get_next_arg()

        #dst_pointers = Utils.get_values_from_cc_arg(dst_argument, state, state.arch)
        #src_pointers = Utils.get_values_from_cc_arg(src_argument, state, state.arch)
        #n_values = Utils.get_values_from_cc_arg(n_argument, state, state.arch)

        #src_values = Utils.get_strings_from_pointers(src_pointers, state, stored_func.code_loc)
        #_new_dst_values = MultiValues()

        #for n in Utils.get_values_from_multivalues(n_values):
        #    _src_values = set()
        #    for value in Utils.get_values_from_multivalues(src_values):
        #        n_val = Utils.get_signed_value(n.concrete_value, state.arch.bits) if n.concrete else -1
        #        if n.symbolic:
        #            value_to_add = Utils.value_of_unknown_size(value, state, cc_to_rd(src_argument, state.arch, state), stored_func.code_loc).one_value()

        #        elif state.is_top(value):
        #            value_to_add = state.top(n.concrete_value * 8)

        #        elif n_val < 0:
        #            value_to_add = Utils.value_of_unknown_size(value, state, cc_to_rd(src_argument, state.arch, state), stored_func.code_loc).one_value()

        #        elif n_val * 8 < value.size():
        #            # truncate the string if needed
        #            value_to_add = value[value.size() - 1: value.size() - n_val * 8]
        #        else:
        #            # we don't have enough bits (or have just enough bits). don't truncate.
        #            value_to_add = value

        #        _src_values.add(value_to_add)

        #    _new_dst_values = _new_dst_values.merge(
        #        MultiValues(offset_to_values={0: _src_values})
        #    )

        ## Evaluate all pointers
        #for dst_pointer in Utils.get_values_from_multivalues(dst_pointers):
        #    if state.is_top(dst_pointer):
        #        self.log.debug("RDA: strncpy(): Destination pointer undefined")
        #    elif isinstance(dst_pointer, (SpOffset, claripy.ast.Base)):
        #        size = max(x.size() for x in Utils.get_values_from_multivalues(_new_dst_values))
        #        memory_location = None
        #        if state.is_stack_address(dst_pointer):
        #            memory_location = MemoryLocation(dst_pointer, size // 8, endness=Endness.BE)
        #        elif state.is_heap_address(dst_pointer):
        #            heap_offset = state.get_heap_offset(dst_pointer)
        #            heap_addr = HeapAddress(heap_offset)
        #            memory_location = MemoryLocation(heap_addr, size // 8, endness=Endness.BE)
        #        elif dst_pointer.concrete and self._project.loader.find_segment_containing(dst_pointer._model_concrete.value) and self._project.loader.find_segment_containing(dst_pointer._model_concrete.value).is_writable:
        #            memory_location = MemoryLocation(dst_pointer._model_concrete.value, size // 8, endness=Endness.BE)
        #        else:
        #            self.log.debug(
        #                "RDA: strncpy(): Invalid destination pointer %#x, sp=%s",
        #                dst_pointer
        #                if isinstance(dst_pointer, int)
        #                else dst_pointer._model_concrete.value,
        #                hex(Utils.get_sp(state))
        #            )
        #        if memory_location:
        #            src_memlocs = {MemoryLocation(src_ptr, size // 8) for src_ptr in
        #                           Utils.get_values_from_multivalues(src_pointers)}
        #            stored_func.depends(memory_location, *src_memlocs, value=_new_dst_values)
        #    else:
        #        self.log.debug(
        #            "RDA: strncpy(): Expected Undefined, integer or Parameter, got %s",
        #            type(dst_pointer).__name__,
        #        )

        #return True, state, dst_pointers

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_strcat(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        """
        Process the impact of the function's execution on register and memory definitions and uses.
        .. sourcecode:: c
            char * strcat ( char * destination, const char * source );
        """
        return self._handle_strcat(state, stored_func)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_strncat(
        self, state: "ReachingDefinitionsState", stored_func: StoredFunction
    ):
        """
        .. sourcecode:: c
            char *strncat(char *dest, const char *src, size_t n);
        """
        self.log.debug("RDA: strncat(): Using strcat(). Size n is ignored.")
        return self._handle_strcat(state, stored_func)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_strlen(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        """
        .. sourcecode:: c
            size_t strlen(const char *s);
        :param LiveDefinitions state:        Register and memory definitions and uses
        :param Codeloc codeloc:              Code location of the call
        """
        self.log.debug("RDA: strlen(), ins_addr=%#x", stored_func.code_loc.ins_addr)

        cc = self._calling_convention_resolver.get_cc("strlen")

        arg_str = cc.get_next_arg()
        str_ptrs = Utils.get_values_from_cc_arg(arg_str, state, state.arch)

        str_values = Utils.get_strings_from_pointers(str_ptrs, state, stored_func.code_loc)

        res = MultiValues()
        for str_ in Utils.get_values_from_multivalues(str_values):
            if state.is_top(str_):
                res.add_value(0, state.top(state.arch.bits))
                self.log.debug("RDA: strlen(): Could not resolve str")
            elif isinstance(str_, claripy.ast.Base):
                res.add_value(0, claripy.BVV(str_.size() // 8, state.arch.bits))
            else:
                self.log.debug(
                    "RDA: strlen(): Expected BVV, got %s",
                    type(str_).__name__,
                )
        if res._values is None:
            res.add_value(0, state.top(state.arch.bits))

        return True, state, res

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_atoi(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        """
        Process the impact of the function's execution on register and memory definitions and uses.
        .. sourcecode:: c
            int atoi (const char * str);
        :param LiveDefinitions state:        Register and memory definitions and uses
        :param Codeloc codeloc:              Code location of the call
        """
        self.log.debug("RDA: atoi(), ins_addr=%#x", stored_func.code_loc.ins_addr)

        cc = self._calling_convention_resolver.get_cc("atoi")

        arg_str = cc.get_next_arg()
        str_ptrs = Utils.get_values_from_cc_arg(arg_str, state, state.arch)

        str_values = Utils.get_strings_from_pointers(str_ptrs, state, stored_func.code_loc)

        res = MultiValues()
        for str_ in Utils.get_values_from_multivalues(str_values):
            if state.is_top(str_) or (
                isinstance(str_, claripy.ast.Base) and not str_.concrete
            ):
                res.add_value(0, state.top(state.arch.bits))
                self.log.debug("RDA: atoi(): Could not resolve str")
            elif isinstance(str_, claripy.ast.Base):
                str_ = Utils.bytes_from_int(str_).decode("latin-1")

                match = re.match(r"^[\t\n\v\f\r]*([+-]?\d+).*$", str_)
                if match is None or match.group(1) == "":
                    res.add_value(0, claripy.BVV(0, state.arch.bits))
                    self.log.debug(
                        "RDA: atoi(): claripy.ast.Base could not be simplified to a string"
                    )
                else:
                    res.add_value(0, claripy.BVV(int(match.group(1)), state.arch.bits))
            else:
                self.log.debug(
                    "RDA: atoi(): Expected claripy.ast.Base, got %s",
                    type(str_).__name__,
                )

        return True, state, res

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_memcpy(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        """
        Process the impact of the function's execution on register and memory definitions and uses.
        .. sourcecode:: c
            void *memcpy(void *dest, const void *src, size_t n);
        :param LiveDefinitions state:        Register and memory definitions and uses
        :param Codeloc codeloc:              Code location of the call
        """
        self.log.debug("RDA: memcpy(), ins_addr=%#x", stored_func.code_loc.ins_addr)

        cc = self._calling_convention_resolver.get_cc("memcpy")

        _get_values_from_cc_arg = lambda argument: Utils.get_values_from_cc_arg(
            argument, state, state.arch
        )
        dest_values = _get_values_from_cc_arg(cc.get_next_arg())
        src_values = _get_values_from_cc_arg(cc.get_next_arg())
        n_values = _get_values_from_cc_arg(cc.get_next_arg())

        # Recover the content to "copy" from memory.
        src_content = Utils.get_strings_from_pointers(src_values, state, stored_func.code_loc)

        # Restrict the content to the number of characters retrieved earlier.

        truncated_mv = MultiValues()
        for length in Utils.get_values_from_multivalues(n_values):
            for offset in src_content.keys():
                for string in src_content[offset]:
                    if (
                        length.concrete
                        and length._model_concrete.value < string.size() // 8
                    ):
                        if length._model_concrete.value != 0:
                            truncated_mv.add_value(
                                offset,
                                string[
                                    : string.size()
                                    - length._model_concrete.value * 8
                                ],
                            )
                        else:
                            truncated_mv.add_value(offset, claripy.BVV(0x0, 8))
                    else:
                        truncated_mv.add_value(offset, string)

        # Set the data of the destination's definitions.
        for value in Utils.get_values_from_multivalues(dest_values):
            size = Utils.get_size_from_multivalue(truncated_mv)
            memory_location = MemoryLocation(value, size)
            src_locations = {MemoryLocation(src_ptr, size) for src_ptr in Utils.get_values_from_multivalues(src_values)}
            stored_func.depends(memory_location, *src_locations, value=truncated_mv)

        return True, state, dest_values

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_memset(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        """
        Process the impact of the function's execution on register and memory definitions and uses.
        .. sourcecode:: c
            void *memset(void *s, int c, size_t n);
        :param LiveDefinitions state:        Register and memory definitions and uses
        :param Codeloc codeloc:              Code location of the call
        """
        self.log.debug("RDA: memset(), ins_addr=%#x", stored_func.code_loc.ins_addr)

        cc = self._calling_convention_resolver.get_cc("memset")

        arg_s = cc.get_next_arg()
        arg_c = cc.get_next_arg()
        arg_n = cc.get_next_arg()

        s_pointer_values = Utils.get_values_from_cc_arg(arg_s, state, state.arch)

        c_values = Utils.get_values_from_cc_arg(arg_c, state, state.arch)
        n_values = Utils.get_values_from_cc_arg(arg_n, state, state.arch)

        s_values = MultiValues()
        for (c, n) in itertools.product(
            Utils.get_values_from_multivalues(c_values),
            Utils.get_values_from_multivalues(n_values),
        ):
            if isinstance(n, claripy.ast.Base) and n.concrete:
                if isinstance(c, claripy.ast.Base) and c.concrete:
                    if n.concrete_value == 0:
                        continue
                    size = (
                        state.arch.bytes
                        if n.concrete_value < 0
                        or (n.concrete_value >> n.size() - 1) == 1
                        else n.concrete_value
                    )
                    value = MultiValues(claripy.BVV(bytes([c.concrete_value & 0xFF] * size), size * 8))
                elif state.is_top(c) or state.is_stack_address(c):
                    definitions = list(state.extract_defs(c))
                    if definitions:
                        value = Utils.unknown_value_of_unknown_size(
                            state, definitions[0].atom, stored_func.code_loc
                        )
                    else:
                        value = MultiValues(state.top(state.arch.bits))
                else:
                    raise ValueError(
                        f"RDA: memset(): Expected Undefined or int for parameter c, got {type(c).__name__}"
                    )
            elif isinstance(n, claripy.ast.Base) and state.is_top(n):
                if isinstance(c, claripy.ast.Base) and c.concrete:
                    value = MultiValues(claripy.BVV(
                        bytes([c.concrete_value & 0xff]) * state.arch.bytes,
                        state.arch.bytes * 8,
                    ))
                elif isinstance(c, claripy.ast.Base) and state.is_top(c):
                    definitions = list(state.extract_defs(c))
                    if definitions:
                        value = Utils.unknown_value_of_unknown_size(
                            state, definitions[0].atom, stored_func.code_loc
                        )
                    else:
                        value = MultiValues(state.top(state.arch.bits))
                else:
                    value = MultiValues(state.top(state.arch.bits))
                    self.log.debug(
                        f"RDA: memset(): Expected TOP or concrete for parameter c, got {type(c).__name__}"
                    )
                self.log.debug("RDA: memset(): Could not resolve n")
            elif isinstance(n, claripy.ast.Base):
                value = MultiValues(state.top(state.arch.bits))
            else:
                raise ValueError(
                    f"RDA: memset(): Expected TOP or concrete for parameter n, got {type(n).__name__}",
                )

            s_values = s_values.merge(value)

        if s_values.count() > 0:
            for destination_pointer in Utils.get_values_from_multivalues(s_pointer_values):
                memory_location = MemoryLocation(
                    destination_pointer, Utils.get_size_from_multivalue(s_values)
                )

                stored_func.depends(memory_location, value=s_values)

        return True, state, s_pointer_values

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_strdup(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        """
        Process the impact of the function's execution on register and memory definitions and uses.
        .. sourcecode:: c
            char *strdup(const char *s);
        """
        self.log.debug("RDA: strdup(), ins_addr=%#x", stored_func.code_loc.ins_addr)

        cc = self._calling_convention_resolver.get_cc("strdup")

        s_argument = cc.get_next_arg()
        s_pointers = Utils.get_values_from_cc_arg(s_argument, state, state.arch)

        s_values = Utils.get_strings_from_pointers(s_pointers, state, stored_func.code_loc)

        # Count the trailing '\0' in the length.
        length = Utils.get_size_from_multivalue(s_values)

        # As per `strdup` manual: "Memory for the new string is obtained with malloc [...]"
        new_string_address = state.heap_allocator.allocate(length)

        # Add values the string can take to the new memory location
        memory_location = MemoryLocation(new_string_address, length, endness=Endness.BE)
        src_locations = {MemoryLocation(ptr, length) for ptr in Utils.get_values_from_multivalues(s_pointers)}
        stored_func.depends(memory_location, *src_locations, value=s_values)

        destination_pointers = MultiValues(claripy.BVV(new_string_address.value, state.arch.bits))

        return True, state, destination_pointers

    def _handle_strstr(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        arch = state.arch
        cc = self._calling_convention_resolver.get_cc("fgets")

        haystack_arg = cc.get_next_arg()
        # needle_arg = cc.get_next_arg()

        return_locations = Utils.get_values_from_cc_arg(haystack_arg, state, arch)
        # needle_ptrs = Utils.get_values_from_cc_arg(needle_arg, state, arch)

        # return_locations = MultiValues()
        # for haystack_ptr in Utils.get_values_from_multivalues(haystack_ptrs):
        #    for haystack_string in Utils.get_values_from_multivalues(Utils.get_strings_from_pointer(haystack_ptr, state, stored_func.code_loc)):
        #        # sp = reach_def.get_sp()
        #        if haystack_string.symbolic:
        #            return_locations.add_value(0, state.top(state.arch.bits))
        #            continue

        #        haystack_str = Utils.bytes_from_int(haystack_string)
        #        for needle in Utils.get_values_from_multivalues(Utils.get_strings_from_pointers(needle_ptrs, state, stored_func.code_loc)):
        #            if needle.symbolic:
        #                return_locations.add_value(0, state.top(state.arch.bits))
        #                continue
        #            needle_str = Utils.bytes_from_int(needle)
        #            if needle_str not in haystack_str:
        #                return_locations.add_value(0, claripy.BVV(0, state.arch.bits))
        #            else:
        #                idx = haystack_str.find(needle_str)
        #                return_locations.add_value(0, haystack_ptr + idx)

        return True, state, return_locations

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_strstr(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        """
        Process read and marks it as taint
        .. sourcecode:: c
            char *strstr(char *haystack, char *needle);
        :param state: Register and memory definitions and uses
        :param codeloc: Code location of the call
        """
        # Instead of doing a full implementation of strstr, we just return the haystack pointer
        self.log.debug("RDA: strstr(), ins_addr=%#x", stored_func.code_loc.ins_addr)

        return self._handle_strstr(state, stored_func)


    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_stristr(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        """
        Instead of doing a full implementation of strtok, we just return the haystack pointer
        .. sourcecode:: c
            char *strtok(char *str, const char *delim);
        """
        self.log.debug("RDA: stristr(), ins_addr=%#x", stored_func.code_loc.ins_addr)

        return self._handle_strstr(state, stored_func)
    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_strchr(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        """
        Instead of doing a full implementation of strtok, we just return the haystack pointer
        .. sourcecode:: c
            char *strtok(char *str, const char *delim);
        """
        self.log.debug("RDA: strchr(), ins_addr=%#x", stored_func.code_loc.ins_addr)

        return self._handle_strstr(state, stored_func)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_strtok(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        """
        Instead of doing a full implementation of strtok, we just return the haystack pointer
        .. sourcecode:: c
            char *strtok(char *str, const char *delim);
        """
        self.log.debug("RDA: strtok(), ins_addr=%#x", stored_func.code_loc.ins_addr)

        return self._handle_strstr(state, stored_func)

        #cc = self._calling_convention_resolver.get_cc("strtok")

        #str_argument = cc.get_next_arg()
        #str_pointers = Utils.get_values_from_cc_arg(str_argument, state, state.arch)

        ## `strtok` is *NOT* a pure function:
        ##   - it modifies the input `str`
        ##   - it has an internal state keeping the `str` passed in its latest call
        #if 0x0 in [
        #    x._model_concrete.value
        #    for x in Utils.get_values_from_multivalues(str_pointers)
        #    if x.concrete
        #]:
        #    if self._strtok_remaining_string_pointers is not None:
        #        self.log.debug("RDA: strtok(): Subsequent calls on the same input string detected, but no pointers have been recorded on a previous call!")
        #        return True, state, MultiValues(claripy.BVV(0x0, 32))

        #    if self._strtok_remaining_string_pointers is None or all(
        #        x.concrete and 0x0 == x._model_concrete.value
        #        for x in Utils.get_values_from_multivalues(
        #            self._strtok_remaining_string_pointers
        #        )
        #    ):
        #        self.log.info("RDA: strtok(): End of string reached")
        #        return True, state, MultiValues(claripy.BVV(0x0, 32))
        #    else:
        #        str_pointers = self._strtok_remaining_string_pointers

        #delim_argument = cc.get_next_arg()
        #delim_pointers = Utils.get_values_from_cc_arg(delim_argument, state, state.arch)
        #delim_values = Utils.get_strings_from_pointers(delim_pointers, state, stored_func.code_loc)

        #def _strtok(string, delimiter) -> Tuple[MultiValues, Optional[MultiValues]]:
        #    """
        #    :return: The token, and the "leftover" string, past the delimiter.
        #    """
        #    if state.is_top(string):
        #        defs = list(state.extract_defs(string))
        #        if defs:
        #            definition = defs[0]
        #            return Utils.unknown_value_of_unknown_size(
        #                state, definition.atom, stored_func.code_loc
        #            ), Utils.unknown_value_of_unknown_size(
        #                state, definition.atom, stored_func.code_loc
        #            )
        #        else:
        #            self.log.debug("No definition exists for string %s.", string)
        #            atom = Register(
        #                str_argument.check_offset(state.arch), str_argument.size
        #            )
        #            return Utils.unknown_value_of_unknown_size(
        #                state, atom, stored_func.code_loc
        #            ), Utils.unknown_value_of_unknown_size(state, atom, stored_func.code_loc)
        #    elif string.concrete:
        #        if delimiter.concrete:
        #            concrete_string = string._model_concrete.value
        #            concrete_delim = delimiter._model_concrete.value
        #            if isinstance(concrete_string, int):
        #                concrete_string = concrete_string.to_bytes(
        #                    string.size() // 8, "big"
        #                )

        #            if isinstance(concrete_delim, int):
        #                concrete_delim = concrete_delim.to_bytes(
        #                    delimiter.size() // 8, "big"
        #                )

        #            index = concrete_string.find(concrete_delim)
        #            if index == -1:
        #                return MultiValues(offset_to_values={0: {string}}), None
        #            return MultiValues(
        #                offset_to_values={0: {string[: index * 8]}}
        #            ), MultiValues(offset_to_values={0: {string[index * 8 :]}})
        #        else:
        #            self.log.debug(
        #                "RDA: strtok(): Expected concrete for parameter delim, got %s",
        #                type(delimiter).__name__,
        #            )
        #            definition = next(state.extract_defs(string))
        #            return Utils.unknown_value_of_unknown_size(
        #                state, definition.atom, stored_func.code_loc
        #            ), Utils.unknown_value_of_unknown_size(
        #                state, definition.atom, stored_func.code_loc
        #            )
        #    else:
        #        self.log.debug(
        #            "RDA: strtok(): Expected Undefined, or str for parameter string, got %s",
        #            type(string).__name__,
        #        )
        #        definition = next(state.extract_defs(string))
        #        return Utils.unknown_value_of_unknown_size(
        #            state, definition.atom, stored_func.code_loc
        #        ), Utils.unknown_value_of_unknown_size(state, definition.atom, stored_func.code_loc)

        ## Keep track of the pointers to the remaining strings (past the first token), to be able to handle subsequent
        ## calls to `strtok` with NULL pointers.
        #remaining_string_pointers = set()
        #return_values = set()
        #for pointer, delimiter in itertools.product(
        #    Utils.get_values_from_multivalues(str_pointers),
        #    Utils.get_values_from_multivalues(delim_values),
        #):
        #    # Try to be as precise as possible for each pointer:
        #    #   - get only the strings pointed to
        #    #   - make the size as small as possible (size of the biggest pointed element)
        #    max_length = 0

        #    for strings in itertools.product(
        #        Utils.get_values_from_multivalues(
        #            Utils.get_strings_from_pointer(pointer, state, stored_func.code_loc)
        #        )
        #    ):
        #        string = functools.reduce(lambda a, b: a.concat(b), strings)
        #        token, leftover = _strtok(string, delimiter)
        #        if leftover:
        #            leftover = leftover.one_value()

        #        if 0 not in token:
        #            continue

        #        for value in token[0]:
        #            return_values |= {value}

        #            # Put the relevant data in the model:
        #            #   - create the memory location corresponding to the start of the remaining string
        #            #   - set the truncated string to the corresponding data
        #            length = value.size() // 8
        #            if Utils.has_unknown_size(value):
        #                pointer_to_leftover = state.top(state.arch.bits)
        #                leftover_length = state.arch.bytes
        #            elif leftover is None or (
        #                isinstance(leftover, claripy.ast.Base)
        #                and leftover.concrete
        #                and leftover._model_concrete.value == 0x0
        #            ):
        #                pointer_to_leftover = claripy.BVV(0x0, state.arch.bits)
        #                leftover_length = 0
        #            else:
        #                pointer_to_leftover = pointer + length
        #                leftover_length = string.size() // 8 - length

        #            if leftover is not None:
        #                memory_location = MemoryLocation(
        #                    pointer_to_leftover, leftover_length
        #                )
        #                try:
        #                    stored_func.depends(memory_location, cc_to_rd(str_argument, state.arch, state))
        #                except SimMemoryError:
        #                    pass

        #                remaining_string_pointers |= {pointer_to_leftover}

        #            max_length = length if length > max_length else max_length

        #    memory_location = MemoryLocation(pointer, max_length)
        #    stored_func.depends(memory_location, cc_to_rd(str_argument, state.arch, state))

        #if not remaining_string_pointers:
        #    empty_pointer = {claripy.BVV(0x0, state.arch.bits)}
        #    self._strtok_remaining_string_pointers = MultiValues(
        #        offset_to_values={0: empty_pointer}
        #    )
        #else:
        #    self._strtok_remaining_string_pointers = MultiValues(
        #        offset_to_values={0: remaining_string_pointers}
        #    )

        #return True, state, self._strtok_remaining_string_pointers if remaining_string_pointers else None
