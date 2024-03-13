import string

import claripy
import logging
import re
import networkx as nx
import itertools
import pprint

from typing import Iterable, Optional, Tuple, Union, List, Set
from functools import lru_cache

from archinfo.arch import Arch
from cle import ELF, PE

import angr
from angr.calling_conventions import SimRegArg, SimStackArg, SimFunctionArgument
from angr.code_location import CodeLocation
from angr.knowledge_plugins.key_definitions.tag import (
    UnknownSizeTag,
)

from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from angr.sim_type import SimTypePointer, SimTypeChar
from angr.knowledge_plugins.functions.function import Function
from angr.knowledge_plugins.key_definitions import LiveDefinitions
from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation, Atom
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER, OP_BEFORE
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.knowledge_plugins.key_definitions.heap_address import HeapAddress
from angr.errors import SimMemoryMissingError
from angr.engines.light import SpOffset
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.analyses.reaching_definitions.dep_graph import DepGraph

from argument_resolver.utils.format_prototype import FormatPrototype

from archinfo import Endness


def _is_stack_pointer(
    ptr: Union[int, SpOffset], sp: Union[int, SpOffset], initial_sp: int
):
    if isinstance(ptr, SpOffset):
        return True
    if isinstance(sp, int):
        return sp <= ptr <= initial_sp

    return False


def _get_strings_from_concrete_memory_area(
    string_pointer: int, state: "ReachingDefinitionsState"
) -> Optional[MultiValues]:
    """
    :param string_pointer: The concrete pointer to a memory region.
    :param state:
    :return: A set of possible string values that can be pointed by string_pointer, or None.
    """

    memory_values = _get_strings_from_pointer(string_pointer, state, state.memory.load)
    return memory_values


# is_pointer = False
# for idx, arg in enumerate(trace.function.calling_convention.arg_locs(trace.function.prototype)):
#    if arg.reg_name == self.project.arch.register_names[defn.atom.reg_offset]:
#        if hasattr(trace.function.prototype.args[idx], "pts_to"):
#            is_pointer = True
#            break


def _get_strings_from_concrete_pointer(
    string_pointer: int, state: "ReachingDefinitionsState", codeloc: CodeLocation
) -> MultiValues:
    """
    :param string_pointer:
    :param state:
    :return: A <MultiValues>.
    """

    # Read data from memory definition, check static memory region if no definition was found
    # or if stack and heap pointers with string stored with load we will load all possible strings
    memory_values = _get_strings_from_concrete_memory_area(string_pointer, state)
    all_undefined = all(
        state.is_top(v) for v in Utils.get_values_from_multivalues(memory_values)
    )

    if memory_values and not all_undefined:
        return memory_values

    project = None
    if isinstance(state, ReachingDefinitionsState):
        project = state.analysis.project
    elif isinstance(state, LiveDefinitions):
        project = state.project

    if project is None:
        return Utils.unknown_value_of_unknown_size(
            state, MemoryLocation(string_pointer, state.arch.bytes * 8), codeloc
        )
    size = 0
    is_null = False
    try:
        while not is_null:
            memory_content = project.loader.memory.load(string_pointer + size, 1)
            is_null = memory_content == b"\x00"
            size += 1 - is_null
        size = size if size != 0 else 1
        memory_content = project.loader.memory.load(string_pointer, size)
        if memory_content == b"\x00":
            memloc = MemoryLocation(string_pointer, state.arch.bytes)
            return Utils.unknown_value_of_unknown_size(state, memloc, codeloc)
        else:
            memloc = MemoryLocation(string_pointer, size)
            values = MultiValues(claripy.BVV(memory_content, size * 8))
            state.kill_and_add_definition(memloc, values, endness=Endness.BE)
            return values
    except KeyError:
        pass

    heap_values = _get_strings_from_pointer(string_pointer, state, state.heap.load)
    return heap_values


def _get_strings_from_heap_offset(
    string_pointer: claripy.ast.Base,
    state: "ReachingDefinitionsState",
    codeloc: CodeLocation,
) -> MultiValues:
    """
    Get string values pointed by string_pointer.
    """
    heap_offset = Utils.get_heap_offset(string_pointer)
    heap_values = _get_strings_from_pointer(heap_offset, state, state.heap.load)

    return heap_values


def _get_strings_from_stack_offset(
    string_pointer: claripy.ast.Base,
    state: "ReachingDefinitionsState",
    codeloc: CodeLocation,
) -> MultiValues:
    """
    Get string values pointed by string_pointer.
    """
    if string_pointer.op == "Reverse":
        stack_pointer = state.get_stack_address(string_pointer.reversed)
    else:
        stack_pointer = state.get_stack_address(string_pointer)

    if stack_pointer is None:
        memloc = MemoryLocation(string_pointer, state.arch.bytes)
        return Utils.unknown_value_of_unknown_size(state, memloc, codeloc)

    stack_values = _get_strings_from_pointer(stack_pointer, state, state.stack.load)

    return stack_values


def _get_strings_from_pointer(pointer, state, load_func):
    new_mv = None
    if pointer is None:
        new_mv = MultiValues()
        new_mv.add_value(0, state.top(state.arch.bits))
        return new_mv
    try:
        mv = load_func(pointer, 1)
    except SimMemoryMissingError:
        return MultiValues(state.top(state.arch.bits))

    for bvv in mv[0]:
        defns = list(state.extract_defs(bvv))
        if len(defns) == 0:
            continue

        max_defn = max(defns, key=lambda x: x.size)
        endness = Endness.BE

        try:
            tmp_mv = load_func(pointer, max_defn.size, endness=endness)
        except SimMemoryMissingError as e:
            if e.missing_size < max_defn.size:
                tmp_mv = load_func(
                    pointer, abs(pointer - e.missing_addr), endness=endness
                )
            else:
                if new_mv is None:
                    new_mv = MultiValues(state.top(max_defn.size * 8))
                else:
                    new_mv = new_mv.merge(MultiValues(state.top(max_defn.size * 8)))
                continue

        mv_dict = {}
        for offset, sub_vals in tmp_mv.items():
            for sub_val in sub_vals:
                if max_defn not in state.extract_defs(sub_val):
                    continue

                for idx in range(sub_val.size() // 8):
                    is_zero = sub_val.get_byte(idx) == 0
                    if is_zero.args[0] is True and idx != 0:
                        if offset not in mv_dict:
                            mv_dict[offset] = set()
                        mv_dict[offset].add(sub_val.get_bytes(0, idx + 1))
                        break
                else:
                    if offset not in mv_dict:
                        mv_dict[offset] = set()
                    mv_dict[offset].add(sub_val)
        if new_mv is None:
            new_mv = MultiValues(mv_dict)
        else:
            new_mv = new_mv.merge(MultiValues(mv_dict))

    if new_mv is None or new_mv.count() == 0:
        new_mv = MultiValues({0: {state.top(state.arch.bits)}})
    return new_mv


class Utils:
    #
    # RDA: Definitions
    #
    log = logging.getLogger("FastFRUIT")
    arch = None

    @staticmethod
    def get_values_from_cc_arg(
        arg: Union[SimStackArg, SimRegArg],
        state: ReachingDefinitionsState,
        arch: Arch,
    ) -> MultiValues:
        """
        Return all definitions for an argument (represented by a calling_conventions' SimRegArg or SimStackArg) from a
        LiveDefinitions object.
        :param arg:              Argument
        :param state:        Register and memory definitions
        :param arch:         Architecture
        :return:             Definition(s) of the argument
        """
        try:
            if isinstance(arg, SimRegArg):
                reg_offset = arch.registers[arg.reg_name][0]
                mv = state.registers.load(reg_offset, size=arch.bytes)
            elif isinstance(arg, SimStackArg):
                sp = Utils.get_sp(state)
                if sp is None:
                    Utils.log.warning("Failed to get stack value, returning TOP")
                    return MultiValues(state.top(arch.bits))
                addr = sp + arg.stack_offset
                if isinstance(addr, SpOffset):
                    mv = state.stack.load(
                        addr.offset, size=arch.bytes, endness=state.arch.memory_endness
                    )
                elif isinstance(addr, int):
                    mv = state.stack.load(
                        addr, size=arch.bytes, endness=state.arch.memory_endness
                    )
                else:
                    raise TypeError(
                        f"Unsupported stack address type {type(addr).__name__}"
                    )
            else:
                raise TypeError(
                    f"Expected SimRegArg or SimStackArg, got {type(arg).__name__}"
                )
            return mv
        except SimMemoryMissingError:
            return MultiValues(state.top(arch.bits))

    @staticmethod
    def get_memory_location_from_bv(ptr_bv: claripy.ast.BV, state, size: int):
        method = Utils.get_store_method_from_ptr(ptr_bv, state)
        if state.is_top(method):
            return None

        return MemoryLocation(method, size)

    #
    # Format strings
    #

    @staticmethod
    def get_prototypes_from_format_string(fmt_string):
        # http://www.cplusplus.com/reference/cstdio/printf
        try:
            fmt_string = fmt_string.decode()
        except (UnicodeDecodeError, AttributeError):
            pass

        flags = r"[-+ #0]"
        width = r"\d+|\*"
        precision = r"\.(?:\d+|\*)"
        length = r"hh|h|l|ll|j|z|t|L"
        # noinspection SpellCheckingInspection
        # specifier = r"[diuoxXfFeEgGaAcspn]"
        specifier = r"[diuoxXcsp\[]"

        # group(0): match
        # group(1) or group(2): specifier
        pattern = rf"(?:%(?:{flags}{{0,5}})(?:{width})?(?:{precision})?(?:{length})?({specifier})|%(%%))"

        # https://docs.python.org/2/library/re.html#re.finditer
        # The string is scanned left-to-right, and matches are returned in the order found.
        if isinstance(fmt_string, bytes):
            pattern = pattern.encode()
        return [
            FormatPrototype(m.group(0), m.group(1) or m.group(2), m.start())
            for m in re.finditer(pattern, fmt_string, re.M)
        ]

    #
    # Strings from pointers
    #
    @staticmethod
    def is_stack_address(addr: claripy.ast.Base) -> bool:
        return "stack_base" in addr.variables

    @staticmethod
    def is_heap_address(addr: claripy.ast.Base) -> bool:
        return "heap_base" in addr.variables

    @staticmethod
    def get_heap_offset(addr: claripy.ast.Base) -> Optional[int]:
        if "heap_base" in addr.variables:
            if addr.op == "BVS":
                return 0
            elif (
                addr.op == "__add__"
                and len(addr.args) == 2
                and addr.args[1].op == "BVV"
            ):
                return addr.args[1]._model_concrete.value
        return None

    @staticmethod
    def gen_heap_address(offset: int, arch: Arch):
        base = claripy.BVS("heap_base", arch.bits, explicit_name=True)
        return base + offset

    @staticmethod
    def gen_stack_address(offset: int, arch: Arch):
        base = claripy.BVS("stack_base", arch.bits, explicit_name=True)
        return base + offset

    @staticmethod
    def get_strings_from_pointer(
        string_pointer: Union[SpOffset, claripy.ast.Base],
        state: "ReachingDefinitionsState",
        codeloc: CodeLocation,
    ) -> MultiValues:
        """
        Retrieve all the potential strings pointed by string_pointer.
        :param string_pointer:
        :param state:
        :param codeloc:
        :return: The potential values of the string pointed by string_pointer in memory.
        """
        if state.is_top(string_pointer):
            # Checking for top values that are also tainted
            if any("@" in x for x in string_pointer.variables):
                return MultiValues(string_pointer)
            memloc = MemoryLocation(string_pointer, state.arch.bytes)
            return Utils.unknown_value_of_unknown_size(state, memloc, codeloc)
        if not string_pointer.symbolic:
            return _get_strings_from_concrete_pointer(
                string_pointer._model_concrete.value, state, codeloc
            )
        elif state.is_stack_address(string_pointer):
            return _get_strings_from_stack_offset(string_pointer, state, codeloc)
        elif Utils.is_heap_address(string_pointer):
            return _get_strings_from_heap_offset(string_pointer, state, codeloc)
        else:
            Utils.log.warning(
                "Strings: Expected int or claripy.ast.Base, got %s",
                type(string_pointer).__name__,
            )
            memloc = MemoryLocation(string_pointer, state.arch.bytes)
            return Utils.unknown_value_of_unknown_size(state, memloc, codeloc)

    @staticmethod
    def get_strings_from_pointers(
        string_pointers: MultiValues,
        state: "ReachingDefinitionsState",
        codeloc: CodeLocation,
    ) -> MultiValues:
        """
        :param string_pointers:
            A MultiValues representing pointers to strings.
            Data content can be of type: <claripy.ast.Base>.
        :param state:
        :param codeloc:
        :return: The values of the string pointed by the string_pointers in memory.
        """
        strings_mv = MultiValues()
        for pointer in Utils.get_values_from_multivalues(string_pointers):
            res = Utils.get_strings_from_pointer(pointer, state, codeloc)
            strings_mv = strings_mv.merge(res)

        return strings_mv

    #
    # Pointers
    #

    @staticmethod
    def is_pointer(ptr, sp, project):
        arch = project.arch
        loader = project.loader

        if (
            isinstance(ptr, (SpOffset, HeapAddress))
            or Utils.is_heap_address(ptr)
            or Utils.is_stack_address(ptr)
        ):
            return True

        if isinstance(ptr, claripy.ast.BV):
            if ptr.concrete:
                ptr = ptr.concrete_value

        if not isinstance(ptr, int):
            return False

        # Check for global variables and static strings
        if isinstance(loader.main_object, ELF):  # ELF
            if len(loader.main_object.sections) > 0:
                section = loader.find_section_containing(ptr)
                if section is not None and section.is_executable is False:
                    return True
            elif loader.find_section_containing(ptr) is not None:
                return True
            elif loader.main_object.min_addr < ptr < loader.main_object.max_addr:
                return True

        elif isinstance(loader.main_object, PE):  # PE
            section = loader.find_section_containing(ptr)
            if section is not None and section.is_executable is False:
                return True

        else:  # Others
            if loader.main_object.min_addr <= ptr <= loader.main_object.max_addr:
                return True

        # Stack
        if isinstance(sp, int):
            if sp <= ptr <= arch.initial_sp:
                return True

        return False

    @staticmethod
    def get_store_method_from_ptr(ptr: claripy.ast.BV, state: ReachingDefinitionsState):
        if ptr.concrete:
            return ptr._model_concrete.value

        if state.is_heap_address(ptr):
            return HeapAddress(state.get_heap_offset(ptr))

        if state.is_stack_address(ptr):
            return SpOffset(state.arch.bits, state.get_stack_offset(ptr))

        return state.top(state.arch.bits)

    @staticmethod
    def get_values_from_multivalues(
        values: MultiValues, pretty=False
    ) -> List[claripy.ast.Base]:
        out_values = {}
        for offset, value_set in sorted(values.items(), key=lambda x: x[0]):
            concat_vals = {}
            known_vals = {}
            for value in value_set:
                defns = list(LiveDefinitions.extract_defs(value)) or [None]
                for new_defn in defns:
                    try:
                        if str(value) in known_vals[new_defn]:
                            continue
                        else:
                            known_vals[new_defn].add(str(value))
                        concat_vals[new_defn].append(value)
                    except KeyError:
                        if offset != 0 and new_defn not in out_values:
                            continue
                        known_vals[new_defn] = {str(value)}
                        concat_vals[new_defn] = [value]

            for defn, vals in concat_vals.items():
                try:
                    out_values[defn].append(vals)
                except KeyError:
                    out_values[defn] = [vals]

        # if pretty is True:
        #    final_vals = []
        #    for x in out_values.values():
        #        for prod in itertools.product(*x):
        #            new_val = None
        #            for y in prod:
        #                if new_val is None:
        #                    new_val = y
        #                else:
        #                    if len(new_val.args) == 3 and len(y.args) == 3 and isinstance(new_val.args[1], int) and isinstance(y.args[1], int):
        #                        if new_val.args[1] - 1 == y.args[0]:
        #                            if y.args[1] == 0:
        #                                new_val = new_val.args[-1]
        #                            else:
        #                                new_val = new_val.args[-1][new_val.args[1]:y.args[1]]
        #                            continue

        #                    new_val = new_val.concat(y)

        #            if new_val is not None:
        #                for idx, final_val in enumerate(final_vals):
        #                    if str(final_val) == str(new_val):
        #                        annotated_val = final_val.annotate(*new_val.annotations)
        #                        final_vals[idx] = annotated_val
        #                        break
        #                else:
        #                    final_vals.append(new_val)

        #    return final_vals

        return [
            y[0].concat(*y[1:]) if len(y) > 1 else y[0]
            for x in out_values.values()
            for y in itertools.product(*x)
        ]

    @staticmethod
    def get_strings_from_multivalues(mv: MultiValues) -> Iterable[claripy.ast.Base]:
        """
        :param mv: The MultiValues object to extract strings from
        :retull possible string value combinationsrn: A list of a
        """
        values = []
        for combo in itertools.product(*mv.values()):
            combined_bvv = claripy.BVV(b"")
            for c in combo:
                combined_bvv = combined_bvv.concat(c)
            values.append(c)
        return values

    @staticmethod
    def bytes_from_int(data: claripy.ast.Base) -> bytes:
        if data.symbolic:
            return data
        output = data.concrete_value.to_bytes(data.size() // 8)
        if output == b"":
            return b"\x00"
        return output

    @staticmethod
    def get_size_from_multivalue(value: MultiValues) -> int:
        max_offset = max(value.keys())
        max_size = max([x.size() for x in value[max_offset]]) // 8
        return max_size + max_offset

    @staticmethod
    def strip_null_from_string(string: claripy.ast.Base) -> claripy.ast.Base:
        if string.symbolic:
            return string

        new_string = Utils.bytes_from_int(string)
        while new_string.endswith(b"\x00"):
            new_string = new_string[:-1]
        result = claripy.BVV(new_string)
        result.annotations = string.annotations

        return result

    @staticmethod
    def unknown_value_of_unknown_size(
        state: "ReachingDefinitionsState", atom: Atom, codeloc: CodeLocation
    ) -> MultiValues:
        return Utils.value_of_unknown_size(
            state.top(state.arch.bytes * 8), state, atom, codeloc
        )

    @staticmethod
    def value_of_unknown_size(
        value, state: "ReachingDefinitionsState", atom: Atom, codeloc: CodeLocation
    ) -> MultiValues:
        atom._size = state.arch.bytes
        tag = UnknownSizeTag(metadata={"tagged_by": "Utils"})
        definition: Definition = Definition(atom, codeloc, dummy=False, tags={tag})
        value = state.annotate_with_def(value, definition)
        mv = MultiValues(offset_to_values={0: {value}})
        return mv

    @staticmethod
    def has_unknown_size(value: claripy.ast.Base) -> bool:
        for annotation in value.annotations:
            if any(
                map(
                    lambda tag: isinstance(tag, UnknownSizeTag),
                    annotation.definition.tags,
                )
            ):
                return True

        return False

    @staticmethod
    def get_signed_value(value: int, size: int):
        unsigned = value % 2**size
        signed = unsigned - 2**size if unsigned >= 2 ** (size - 1) else unsigned
        return signed

    @staticmethod
    def get_sp(state: ReachingDefinitionsState) -> int:
        try:
            sp = state.get_sp()
        except AssertionError:
            sp_values: MultiValues = state.registers.load(
                state.arch.sp_offset, size=state.arch.bytes
            )
            next_vals = next(iter(sp_values.values()))
            if len(next_vals) == 0:
                raise AssertionError
            else:
                sp = max(
                    state.get_stack_address(x)
                    for x in next_vals
                    if state.get_stack_address(x) is not None
                )
        return sp

    @staticmethod
    def get_definition_dependencies(
        graph: DepGraph, target_defns: Set[Definition], is_root=False
    ) -> Set[Definition]:
        """
        Recursively get all definitions that our target depends on
        :param stored_func:
        :param target_atoms:
        :return:
        """

        # Get all root nodes of the dependency tree based on the target definitions
        if not is_root:
            graph = graph.graph.reverse(True)
        else:
            graph = graph.graph

        # Get all nodes reachable from the root nodes
        dependent_defns: Set[Definition] = set()
        for defn in {x for x in target_defns if x in graph}:
            dependent_defns |= set(nx.dfs_preorder_nodes(graph, source=defn))
        return dependent_defns

    @staticmethod
    def get_all_dependant_functions(
        func_list: List["StoredFunction"],
        graph: DepGraph,
        target_defns: Set[Definition],
        is_root=False,
    ):
        defns = Utils.get_definition_dependencies(graph, target_defns, is_root=is_root)
        dependant_funcs = []
        for func in func_list:
            if any(x in defns for x in func.all_definitions):
                dependant_funcs.append(func)
        return dependant_funcs

    @staticmethod
    @lru_cache
    def get_all_callsites(project: angr.Project):
        """
        Retrieve all function callsites
        :return:
            A list of tuples, for each sink present in the binary, containing: the representation of the <Sink> itself, the <Function> representation,
            and the list of addresses in the binary the sink is called from.
        """

        def _call_statement_in_node(node) -> Tuple[str, int, OP_AFTER]:
            """
            Assuming the node is the predecessor of a function start.
            Returns the statement address of the `call` instruction.
            """
            if len(node.block.disassembly.insns) < 2:
                return None
            addrs = [x.address for x in node.block.disassembly.insns]
            addr = addrs[-1]
            if project.arch.branch_delay_slot:
                if node.block.disassembly.insns[-1].mnemonic == "nop":
                    addr = addrs[-2]

            return "insn", addr, OP_AFTER

        cfg = project.kb.cfgs.get_most_accurate()
        final_callsites = []
        for func in project.kb.functions.values():
            if cfg.get_any_node(func.addr) is None:
                continue

            calling_nodes = [
                x
                for x in cfg.get_any_node(func.addr).predecessors
                if x.block is not None and not x.has_return
            ]
            if calling_nodes:
                calling_insns = list(
                    filter(
                        lambda x: x is not None,
                        map(_call_statement_in_node, calling_nodes),
                    )
                )
                calling_insns.append(("node", func.addr, OP_BEFORE))
                pre_nodes = [("node", x.addr, OP_BEFORE) for x in calling_nodes]
                pre_nodes += [("node", x.addr, OP_AFTER) for x in calling_nodes]
                final_callsites.extend(calling_insns + pre_nodes)
            for x in func.ret_sites + func.jumpout_sites:
                final_callsites.append(("node", x.addr, OP_AFTER))
        return final_callsites

    @staticmethod
    def value_from_simarg(
        simarg: SimFunctionArgument, livedef: LiveDefinitions, arch: Arch
    ):
        if isinstance(simarg, SimRegArg):
            mv = livedef.registers.load(*arch.registers[simarg.reg_name])
        elif isinstance(simarg, SimStackArg):
            mv = livedef.stack.load(
                livedef.get_sp() + simarg.stack_offset,
                arch.bytes,
                endness=arch.memory_endness,
            )
        else:
            raise Exception(f"SimArg Value {simarg} not Handled")
        return mv

    @staticmethod
    def is_in_text_section(definition, project) -> bool:
        res = project.loader.find_section_containing(definition.codeloc.ins_addr)
        if res is None:
            return False
        if res.name != ".text":
            return False
        return True

    @staticmethod
    def arguments_from_function(function: Function):
        arguments = function.arguments
        cc = function.calling_convention
        if cc and any(
            not isinstance(x, SimRegArg) and not isinstance(x, SimStackArg)
            for x in arguments
        ):
            session = cc.arg_session(None)
            new_args = []
            prototype_args = function.prototype.args
            for idx, arg in enumerate(arguments):
                if not isinstance(arg, SimRegArg) or not isinstance(arg, SimStackArg):
                    new_arg = cc.next_arg(
                        session,
                        SimTypePointer(SimTypeChar().with_arch(cc.ARCH)).with_arch(
                            cc.ARCH
                        ),
                    )
                else:
                    new_arg = cc.next_arg(session, prototype_args[idx])
                new_args.append(new_arg)

            arguments = new_args
        if not arguments:
            # Handler.function_cache[tuple([function])] = True
            return []
        return arguments

    @staticmethod
    def get_atoms_from_function(function: Function, registers: list):
        function_arguments = Utils.arguments_from_function(function)
        atoms = [Atom.from_argument(x, registers) for x in function_arguments]
        return atoms

    @staticmethod
    def get_callstring_for_function(
        function: Function, callsites: List["CallSite"], codeloc: CodeLocation
    ) -> List[int]:
        chain = [codeloc.ins_addr]
        all_callsites = set()
        for callsite in reversed(callsites):
            all_callsites.add(callsite.caller_func_addr)
            all_callsites.add(callsite.callee_func_addr)
        chain.extend(sorted(list(all_callsites)))
        return chain

    @staticmethod
    def get_func_tuple(function: Function, subject, registers, codeloc):
        atoms = Utils.get_atoms_from_function(function, registers)
        if isinstance(subject, Function) or isinstance(subject.content, Function):
            call_string = [codeloc.ins_addr]
        else:
            call_string = Utils.get_callstring_for_function(
                function, subject.content.callsites, codeloc
            )

        func_tuple = tuple([function] + atoms + call_string)
        return func_tuple

    @staticmethod
    def get_concrete_value_from_int(mv: MultiValues) -> Union[List[int], None]:
        out = None
        vals = Utils.get_values_from_multivalues(mv)
        if all(x.concrete for x in vals):
            out = [x.concrete_value for x in vals]

        return out

    @staticmethod
    def get_bv_from_atom(atom: Atom, arch: Arch):
        if isinstance(atom.addr, SpOffset):
            return Utils.gen_stack_address(atom.addr.offset, arch)
        elif isinstance(atom.addr, HeapAddress):
            return Utils.gen_heap_address(atom.addr.value, arch)
        elif isinstance(atom.addr, int):
            return claripy.BVV(atom.addr, arch.bits)
        return None
