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


class StdioHandlers(HandlerBase):
    """
    Handlers for <stdio.h>'s functions.
    """

    # TODO Handle strstr

    def _handle_sprintf(
        self,
        state: "ReachingDefinitionsState",
        stored_func: StoredFunction,
        concretize_nums: bool = True,
    ):
        """
        :param state: Register and memory definitions and uses
        :param codeloc: Code location of the call
        :param handler_name: Name of the "real" handler, called originally.
        """
        arch = state.arch

        self.log.debug("RDA: %s(), ins_addr=%#x", stored_func.name, stored_func.code_loc.ins_addr)

        in_place = stored_func.name in ["doSystemCmd", "twsystem", "exec_cmd", "execFormatCmd"]
        if in_place:
            cc = self._calling_convention_resolver.get_cc("printf")
        else:
            cc = self._calling_convention_resolver.get_cc(stored_func.name)
        # Get sim function arguments

        if not in_place:
            arg_dst = cc.get_next_arg()

        if stored_func.name in ["sprintf", "asprintf", "vsprintf"] or in_place:
            arg_fmt = cc.get_next_arg()
            # num_fixed_args = 2
        elif stored_func.name in ["snprintf", "vsnprintf"]:
            cc.get_next_arg()  # args[1]: size
            arg_fmt = cc.get_next_arg()
            # num_fixed_args = 3
        elif stored_func.name == "__sprintf_chk":
            cc.get_next_arg()  # args[1]: flag
            cc.get_next_arg()  # args[2]: strlen
            arg_fmt = cc.get_next_arg()
            # num_fixed_args = 4
        elif stored_func.name == "__snprintf_chk":
            cc.get_next_arg()  # args[1]: maxlen
            cc.get_next_arg()  # args[2]: flag
            cc.get_next_arg()  # args[3]: strlen
            arg_fmt = cc.get_next_arg()
            # num_fixed_args = 5
        else:
            raise ValueError(stored_func.name)

        # Generate a single MultiValues that includes all possible sources / destinations
        if not in_place:
            dst_ptrs = Utils.get_values_from_cc_arg(arg_dst, state, arch)
        fmt_ptrs = Utils.get_values_from_cc_arg(arg_fmt, state, arch)

        # Get all concrete format strings
        fmt_strs = Utils.get_strings_from_pointers(fmt_ptrs, state, stored_func.code_loc)

        cont = True
        if len(list(Utils.get_values_from_multivalues(fmt_strs))) == 0:
            cont = False
            self.log.debug("RDA: %s(): No (concrete) format string found", stored_func.name)

        # Get all concrete destination pointer
        if cont and not in_place:
            dst_int_ptrs = [x for x in Utils.get_values_from_multivalues(dst_ptrs) if not state.is_top(x)]
        else:
            dst_int_ptrs = []

        if not in_place and len(dst_int_ptrs) == 0:
            cont = False
            self.log.debug("RDA: %s(): No (concrete) destination found", stored_func.name)

        formatted_strs = None
        if cont:
            fmt_args = {}
            for fmt_str in [x for x in Utils.get_values_from_multivalues(fmt_strs) if x.concrete]:
                fmt_prototypes = Utils.get_prototypes_from_format_string(
                    Utils.bytes_from_int(fmt_str)
                )
                num_prototypes = len(fmt_prototypes)
                if num_prototypes == 0:
                    # Handle format string w/o format prototypes
                    if formatted_strs is None:
                        formatted_strs = MultiValues(fmt_str)
                    else:
                        formatted_strs.add_value(0, fmt_str)
                else:
                    # res describes the result of a format string. Each element is a list which either includes a
                    # static part of the format string or the resolved values of a prototype. E.g. 'ls %s' leads to
                    # res = [['ls '], [<values for %s>]].
                    res: List[List[Union[str, claripy.ast.BV]]] = []

                    # Extract static part in front of the first prototype
                    if fmt_prototypes[0].position and fmt_str.concrete:
                        prologue_len = ((fmt_str.size() // 8) - fmt_prototypes[0].position) * 8
                        res.append([fmt_str[:prologue_len]])

                    # Process each prototype and the consecutive static part of the format string
                    for i in range(num_prototypes):
                        fmt_prototype = fmt_prototypes[i]
                        fmt_prototype = fmt_prototype.decode() if isinstance(fmt_prototype, bytes) else fmt_prototype

                        # Prototype
                        values = []
                        # noinspection SpellCheckingInspection
                        if fmt_prototype.specifier in "diuoxX":
                            if i not in fmt_args:
                                arg = cc.get_next_arg()
                                fmt_args[i] = arg
                            mv = Utils.get_values_from_cc_arg(fmt_args[i], state, arch)
                            for value in Utils.get_values_from_multivalues(mv):
                                if value.concrete:
                                    values.append(
                                        claripy.BVV(
                                            str(value._model_concrete.value).encode()
                                        )
                                    )
                                elif concretize_nums:
                                    values.append(claripy.BVV(b"1337"))
                                else:
                                    values.append(value)
                        elif fmt_prototype.specifier in "s":
                            if i not in fmt_args:
                                arg = cc.get_next_arg()
                                fmt_args[i] = arg

                            src_ptrs = Utils.get_values_from_cc_arg(
                                fmt_args[i], state, arch
                            )

                            # get the actual values
                            strings = Utils.get_strings_from_pointers(
                                src_ptrs, state, stored_func.code_loc
                            )
                            string_values = Utils.get_values_from_multivalues(strings)
                            if any(len(x.annotations) == 0 for x in strings[0]):
                                mem_loc = MemoryLocation(
                                    src_ptrs.one_value(),
                                    Utils.get_size_from_multivalue(strings) // 8,
                                    endness=Endness.BE
                                )
                                stored_func.depends(mem_loc, value=strings, apply_at_callsite=True)

                            for val in string_values:
                                if not state.is_top(val) and Utils.has_unknown_size(
                                    val
                                ):
                                    val.length = state.arch.bytes * 8
                                values.append(val)

                        elif fmt_prototype.specifier in "c":
                            values.append(claripy.BVV(b"|"))
                        else:
                            self.log.debug(
                                "RDA: %s(): Specifier %%%s not supported",
                                stored_func.name,
                                fmt_prototype.specifier,
                            )

                        if values:
                            res.append(values)

                        # Static part
                        if i < num_prototypes - 1:
                            end = fmt_prototypes[i + 1].position
                        else:
                            end = fmt_str.size() // 8
                        s = Utils.bytes_from_int(fmt_str)[
                            fmt_prototype.position + len(fmt_prototype.prototype) : end
                        ].decode("latin-1")
                        if s not in ("", "\x00"):
                            res.append([s])

                    # Create a DataRelation for each permutation of res
                    for combinations in list(itertools.product(*res)):
                        out_str = None
                        for str_ in combinations:
                            if isinstance(str_, str):
                                str_ = claripy.BVV(str_.encode("latin-1"))
                            if out_str is None:
                                out_str = str_
                            else:
                                out_str = out_str.concat(str_)

                        if formatted_strs is None:
                            formatted_strs = MultiValues(out_str)
                        else:
                            formatted_strs = formatted_strs.merge(MultiValues(out_str))

            # Add definition of resolved format string for all concrete destinations
            if formatted_strs is not None and formatted_strs.count() > 0 and not in_place:
                for dst_ptr in dst_int_ptrs:
                    sources = stored_func.atoms - {cc_to_rd(arg_dst, state.arch, state)}
                    if stored_func.name == "asprintf":
                        alloc_size = Utils.get_size_from_multivalue(formatted_strs)
                        heap_addr = state.heap_allocator.allocate(alloc_size)
                        memloc = MemoryLocation(heap_addr, alloc_size, endness=Endness.BE)
                        stored_func.depends(memloc, *stored_func.atoms, value=formatted_strs)
                        heap_ptr = MultiValues(Utils.gen_heap_address(heap_addr.value, state.arch))
                        store_loc = Utils.get_memory_location_from_bv(dst_ptr, state, state.arch.bytes)
                        stored_func.depends(store_loc, memloc, value=heap_ptr)
                    else:
                        memloc = MemoryLocation(dst_ptr, Utils.get_size_from_multivalue(formatted_strs), endness=Endness.BE)
                        stored_func.depends(memloc, *sources, value=formatted_strs)
            elif in_place and formatted_strs is not None:
                first_arg = cc_to_rd(arg_fmt, state.arch, state)
                stored_func._arg_vals[first_arg] = formatted_strs
                vals = Utils.get_values_from_multivalues(formatted_strs)
                stored_func.constant_data[first_arg] = vals if all(v.concrete for v in vals) else None
                return True, state, MultiValues(claripy.BVV(0, 32))

        # Add definition for return value
        if cont and formatted_strs is not None:
            number_of_symbols = self._number_of_symbols_for_formatted_strings(formatted_strs, state)
            if number_of_symbols.count() == 0:
                number_of_symbols = MultiValues(state.top(state.arch.bits))
        else:
            number_of_symbols = MultiValues(state.top(state.arch.bits))

        return True, state, number_of_symbols

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_sprintf(
        self, state: "ReachingDefinitionsState", stored_func: StoredFunction
    ):
        """
        Process the impact of the function's execution on register and memory definitions and uses.

        .. sourcecode:: c

            int sprintf ( char * str, const char * format, ... );

        :param state: Register and memory definitions and uses
        :param codeloc: Code location of the call
        """
        return self._handle_sprintf(state, stored_func)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_vsprintf(
        self, state: "ReachingDefinitionsState", stored_func: StoredFunction
    ):
        """
        Process the impact of the function's execution on register and memory definitions and uses.

        .. sourcecode:: c

            int sprintf ( char * str, const char * format, ... );

        :param state: Register and memory definitions and uses
        :param codeloc: Code location of the call
        """
        return self._handle_sprintf(state, stored_func)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_snprintf(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        """
        .. sourcecode:: c

            int snprintf(char *str, size_t size, const char *format, ...);
        """
        self.log.debug("RDA: snprintf(): Using sprintf(). Size n is ignored.")
        return self._handle_sprintf(state, stored_func)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_vsnprintf(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        """
        .. sourcecode:: c

            int snprintf(char *str, size_t size, const char *format, ...);
        """
        self.log.debug("RDA: vsnprintf(): Using sprintf(). Size n is ignored.")
        return self._handle_sprintf(state, stored_func)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_asprintf(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        """
        .. sourcecode:: c

            int snprintf(char *str, size_t size, const char *format, ...);
        """
        self.log.debug("RDA: asprintf(): Using sprintf().")
        return self._handle_sprintf(state, stored_func)

    # TODO Handle __sprintf_chk __snprintf_chk strstr

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle___sprintf_chk(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        """
        .. sourcecode:: c

            int __sprintf_chk(char *str, int flag, size_t strlen, const char *format, ...);
        """
        self.log.debug("RDA: __sprintf_chk(): Using sprintf(). Size n is ignored.")
        return self._handle_sprintf(state, stored_func)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle___snprintf_chk(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        """
        .. sourcecode:: c

            int __snprintf_chk(char *str, size_t maxlen, int flag, size_t strlen, const char *format, ...);
        """
        self.log.debug("RDA: __snprintf_chk(): Using sprintf(). Size n is ignored.")
        return self._handle_sprintf(state, stored_func)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_printf(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        return False, state, None

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_twsystem(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):

        self.log.debug("RDA: Using sprintf() to handle twsystem")
        return self._handle_sprintf(state, stored_func)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_exec_cmd(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):

        self.log.debug("RDA: Using sprintf() to handle %s", stored_func.name)
        return self._handle_sprintf(state, stored_func)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_doSystemCmd(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):

        self.log.debug("RDA: Using sprintf() to handle doSystemCmd")
        return self._handle_sprintf(state, stored_func)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_dprintf(self,  state: "ReachingDefinitionsState", stored_func: StoredFunction):
        return False, state, None

    def _handle_scanf(self,
                      state: "ReachingDefinitionsState",
                      stored_func: StoredFunction,
                      concretize_nums: bool = True):
        arch = state.arch

        self.log.debug("RDA: %s(), ins_addr=%#x", stored_func.name, stored_func.code_loc.ins_addr)

        cc = self._calling_convention_resolver.get_cc(stored_func.name)

        # Get sim function arguments
        arg_src = None
        if stored_func.name.replace('__isoc99_', '') in {"sscanf", "fscanf"}:
            arg_src = cc.get_next_arg()
            # num_fixed_args = 2
        arg_fmt = cc.get_next_arg()

        fmt_ptrs = Utils.get_values_from_cc_arg(arg_fmt, state, arch)

        # Get all concrete format strings
        fmt_strs = Utils.get_strings_from_pointers(fmt_ptrs, state, stored_func.code_loc)

        if fmt_strs.count() == 0:
            self.log.debug("RDA: %s(): No (concrete) format string found", stored_func.name)
            return False, state

        # Get all concrete destination pointer
        fmt_args = {}
        for fmt_str in [x for x in Utils.get_values_from_multivalues(fmt_strs) if x.concrete]:
            fmt_prototypes = Utils.get_prototypes_from_format_string(
                Utils.bytes_from_int(fmt_str)
            )
            num_prototypes = len(fmt_prototypes)
            if num_prototypes == 0:
                # Handle format string w/o format prototypes
                continue

            # Process each prototype and the consecutive static part of the format string
            for i, fmt_prototype in enumerate(fmt_prototypes):
                if '*' in fmt_prototype.prototype:
                    continue

                if i not in fmt_args:
                    arg = cc.get_next_arg()
                    fmt_args[i] = {"arg": arg, "value": None}

                mv = MultiValues(state.top(state.arch.bits))
                if fmt_prototype.specifier in "diuoxX":
                    mv = MultiValues(claripy.BVV(0x1337, state.arch.bits))
                elif arg_src:
                    src_ptrs = Utils.get_values_from_cc_arg(
                        arg_src, state, arch
                    )
                    new_mv = MultiValues()
                    for src_ptr in Utils.get_values_from_multivalues(src_ptrs):
                        if state.is_top(src_ptr):
                            new_mv.add_value(0, src_ptr)
                        else:
                            if new_mv.count() > 0:
                                new_mv = new_mv.merge(Utils.get_strings_from_pointers(src_ptrs, state, stored_func.code_loc))
                            else:
                                new_mv = Utils.get_strings_from_pointers(src_ptrs, state, stored_func.code_loc)
                    mv = new_mv

                if fmt_args[i]["value"] is None:
                    fmt_args[i]["value"] = mv
                else:
                    fmt_args[i]["value"] = fmt_args[i]["value"].merge(mv)

        for val_dict in fmt_args.values():
            arg = val_dict["arg"]
            val = val_dict["value"]
            dst_ptrs = Utils.get_values_from_cc_arg(arg, state, arch)

            # Add definition of resolved format string for all concrete destinations
            dst_int_ptrs = [x for x in Utils.get_values_from_multivalues(dst_ptrs) if not state.is_top(x)]
            for dst_ptr in dst_int_ptrs:
                if not state.is_top(dst_ptr):
                    memloc = MemoryLocation(Utils.get_store_method_from_ptr(dst_ptr, state), Utils.get_size_from_multivalue(val))
                    sources = {cc_to_rd(arg_src, state.arch, state)} if arg_src else set()
                    stored_func.depends(memloc, *sources, value=val)
                else:
                    self.log.debug("Failed to store to %s: Unresolvable Destination", val)

        number_of_symbols = MultiValues(claripy.BVV(len(fmt_args), state.arch.bits))
        return True, state, number_of_symbols
    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_sscanf(self, state: "ReachingDefinitionsState", stored_func: StoredFunction):
        return self._handle_scanf(state, stored_func)


    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_fgets(self, state: ReachingDefinitionsState, stored_func: StoredFunction):
        """
        Process read and marks it as taint
        .. sourcecode:: c
            char *fgets(char *s, int size, FILE *stream);
        :param state: Register and memory definitions and uses
        :param codeloc: Code location of the call
        """
        self.log.debug("RDA: fgets(), ins_addr=%#x", stored_func.code_loc.ins_addr)

        arch = state.arch
        cc = self._calling_convention_resolver.get_cc("fgets")

        arg_buf = cc.get_next_arg()
        arg_count = cc.get_next_arg()
        arg_stream = cc.get_next_arg()

        buf_ptrs = Utils.get_values_from_cc_arg(arg_buf, state, arch)
        size = Utils.get_values_from_cc_arg(arg_count, state, arch)
        stream = Utils.get_values_from_cc_arg(arg_stream, state, arch)

        parent_fds = []
        parent = None
        for val in Utils.get_values_from_multivalues(stream):
            if val.concrete and val.concrete_value in self.fd_tracker:
                parent_fds.append(val.concrete_value)
                if parent is None:
                    parent = self.fd_tracker[val.concrete_value]["val"]
                else:
                    parent = parent.concat(self.fd_tracker[val.concrete_value]["val"])

        for ptr in Utils.get_values_from_multivalues(buf_ptrs):
            # sp = reach_def.get_sp()
            size_val = Utils.get_concrete_value_from_int(size)
            size_val = max(size_val) if size_val is not None else state.arch.bytes
            size_val = min(size_val, self.MAX_READ_SIZE)
            memloc = MemoryLocation(ptr, size_val)
            if parent is not None:
                parent_name = next(iter(x for x in parent.variables if x != "TOP"))
            else:
                parent_name = "?"
            buf_bvs = claripy.BVS(
                f"{stored_func.name}({parent_name})@0x{stored_func.code_loc.ins_addr:x}",
                memloc.size*8)
            buf_bvs.variables = frozenset(set(buf_bvs.variables) | {"TOP"})

            if stored_func.name not in self.fd_tracker:
                self.fd_tracker[stored_func.name] = []

            self.fd_tracker[stored_func.name].append(
                {"val": buf_bvs, "parent": parent_fds, "ins_addr": stored_func.code_loc.ins_addr})
            stored_func.depends(memloc, *stored_func.atoms, value=MultiValues(buf_bvs))

        return True, state, buf_ptrs

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_fopen(self, state: ReachingDefinitionsState, stored_func: StoredFunction):
        """
        Process read and marks it as taint
        .. sourcecode:: c
            FILE* fopen(char *path, const char *mode);
        :param state: Register and memory definitions and uses
        :param codeloc: Code location of the call
        """
        self.log.debug("RDA: fopen(), ins_addr=%#x", stored_func.code_loc.ins_addr)

        arch = state.arch
        cc = self._calling_convention_resolver.get_cc("fopen")

        arg_path = cc.get_next_arg()
        arg_mode = cc.get_next_arg()

        path_ptrs = Utils.get_values_from_cc_arg(arg_path, state, arch)
        mode_ptrs = Utils.get_values_from_cc_arg(arg_mode, state, arch)

        path = Utils.get_strings_from_pointers(path_ptrs, state, stored_func.code_loc)
        paths = []
        for p in Utils.get_values_from_multivalues(path):
            if p.concrete:
                paths.append(f'"{Utils.bytes_from_int(p).decode("latin-1")}"')
            else:
                paths.append(f'"{p}"')

        mode = Utils.get_strings_from_pointers(mode_ptrs, state, stored_func.code_loc)
        modes = []
        for m in Utils.get_values_from_multivalues(mode):
            if m.concrete:
                modes.append(f'"{Utils.bytes_from_int(m).decode("latin-1")}"')
            else:
                modes.append(f'"{m}"')

        fd = self.gen_fd()
        buf_bvs = claripy.BVS(
            f"{stored_func.name}({' | '.join(sorted(paths))}, {' | '.join(sorted(modes))})@0x{stored_func.code_loc.ins_addr:x}",
            state.arch.bits)
        buf_bvs.variables = frozenset(set(buf_bvs.variables) | {"TOP"})

        self.fd_tracker[fd] = {"val": buf_bvs, "parent": None, "ins_addr": None}

        return True, state, MultiValues(claripy.BVV(fd, state.arch.bits))

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_fread(self, state: ReachingDefinitionsState, stored_func: StoredFunction):
        """
        Process read and marks it as taint
        .. sourcecode:: c
            char *fread(char *s, int size, size_t nmemb, FILE *stream);
        :param state: Register and memory definitions and uses
        :param codeloc: Code location of the call
        """
        self.log.debug("RDA: fgets(), ins_addr=%#x", stored_func.code_loc.ins_addr)

        arch = state.arch
        cc = self._calling_convention_resolver.get_cc("fread")

        arg_buf = cc.get_next_arg()
        arg_size = cc.get_next_arg()
        arg_nmemb = cc.get_next_arg()
        arg_stream = cc.get_next_arg()

        buf_ptrs = Utils.get_values_from_cc_arg(arg_buf, state, arch)
        size = Utils.get_values_from_cc_arg(arg_size, state, arch)
        nmemb = Utils.get_values_from_cc_arg(arg_nmemb, state, arch)
        stream = Utils.get_values_from_cc_arg(arg_stream, state, arch)

        size_val = Utils.get_concrete_value_from_int(size)
        size_val = max(size_val) if size_val is not None else state.arch.bytes

        nmemb_val = Utils.get_concrete_value_from_int(nmemb)
        nmemb_val = max(nmemb_val) if nmemb_val is not None else state.arch.bytes

        parent_fds = []
        parent = None
        for val in Utils.get_values_from_multivalues(stream):
            if val.concrete and val.concrete_value in self.fd_tracker:
                parent_fds.append(val.concrete_value)
                if parent is None:
                    parent = self.fd_tracker[val.concrete_value]["val"]
                else:
                    parent = parent.concat(self.fd_tracker[val.concrete_value]["val"])

        if stored_func.name not in self.fd_tracker:
            self.fd_tracker[stored_func.name] = []

        for ptr in Utils.get_values_from_multivalues(buf_ptrs):
            size = min(size_val*nmemb_val, 0x1000)
            memloc = MemoryLocation(ptr, size)

            if parent is not None:
                parent_name = next(iter(x for x in parent.variables if x != "TOP"))
            else:
                parent_name = "?"
            buf_bvs = claripy.BVS(
                f"{stored_func.name}({parent_name})@0x{stored_func.code_loc.ins_addr:x}",
                memloc.size*8)
            buf_bvs.variables = frozenset(set(buf_bvs.variables) | {"TOP"})
            mv = MultiValues(buf_bvs)
            self.fd_tracker[stored_func.name].append(
                {"val": buf_bvs, "parent": parent_fds, "ins_addr": stored_func.code_loc.ins_addr})
            stored_func.depends(memloc, *stored_func.atoms, value=mv, apply_at_callsite=True)

        return True, state, MultiValues(state.top(state.arch.bits))

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_popen(self, state: ReachingDefinitionsState, stored_func: StoredFunction):
        return False, state, None

    def _number_of_symbols_for_formatted_strings(
        self, formatted_strings: MultiValues, state: ReachingDefinitionsState
    ) -> MultiValues:
        data_number_of_symbols = MultiValues()
        for s in Utils.get_values_from_multivalues(formatted_strings):
            if isinstance(s, claripy.String):
                data_number_of_symbols.add_value(
                    0, claripy.BVV(s.string_length - 1, state.arch.bits)
                )
            elif state.is_top(s):
                return MultiValues(offset_to_values={0: {state.top(state.arch.bits)}})
            else:
                data_number_of_symbols.add_value(
                    0, claripy.BVV(len(s), state.arch.bits)
                )

        return data_number_of_symbols
