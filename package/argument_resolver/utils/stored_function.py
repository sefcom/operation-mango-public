from typing import Dict, Set, Optional

from angr.sim_type import SimTypePointer, SimTypeChar
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.analyses.reaching_definitions.function_handler import FunctionCallData
from angr.knowledge_plugins.key_definitions.atoms import (
    Atom,
    Register,
    MemoryLocation,
    SpOffset,
)
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues

from angr.code_location import CodeLocation

from .transitive_closure import transitive_closures_from_defs, get_constant_data
from .utils import Utils
from .calling_convention import CallingConventionResolver, cc_to_rd

from archinfo import Endness


class StoredFunction:
    def __init__(
        self,
        state: ReachingDefinitionsState,
        data: FunctionCallData,
        call_stack,
        depth: int,
    ):

        self._data = data
        self.depth = depth + 1
        self.target_defns: Set[Definition] = set()
        self.state = state
        self.definitions: Set[Definition] = set()
        self.return_definitions: Set[Definition] = set()
        self.call_stack = {x.code_loc.ins_addr for x in call_stack[1:]}
        self._constant_data = {}
        self._return_data = {}
        self._arg_vals = {}
        self._ret_val = None
        self._closures = None
        self._function = None
        self._hash = None

    @property
    def constant_data(self):
        return self._constant_data

    @property
    def subject(self):
        return self.state._subject

    @property
    def return_data(self):
        if not self._return_data:
            pass
        return self._return_data

    @property
    def name(self):
        return self._data.name

    @property
    def arg_vals(self):
        if not self._arg_vals:
            self._arg_vals = self.get_arg_vals()
        return self._arg_vals

    @property
    def args_atoms(self):
        return self._data.args_atoms

    @property
    def code_loc(self):
        return self._data.callsite_codeloc

    @property
    def atoms(self):
        atoms = {y for x in self.args_atoms for y in x}
        for atom in atoms:
            if atom not in self.constant_data:
                self._constant_data[atom] = None
            if hasattr(atom, "endness") and atom.endness is None:
                atom.endness = self.state.arch.memory_endness
        return atoms

    @property
    def visited_blocks(self):
        return self._data.visited_blocks

    @property
    def function(self):
        addr = self._data.function_codeloc.block_addr
        if (
            self._data.function is None
            and addr
            and addr in self.state.analysis.project.kb.functions
        ):
            self._function = self.state.analysis.project.kb.functions[addr]
        else:
            self._function = self._data.function

        return self._function

    @property
    def ret_atoms(self):
        return self._data.ret_atoms

    @property
    def closures(self):
        self.save_closures()

        return self._closures

    @property
    def ret_val(self):
        return self._ret_val

    @property
    def all_definitions(self):
        return self.definitions | self.return_definitions

    def depends(
        self,
        dest: Optional[Atom],
        *sources: Atom,
        value: Optional[MultiValues] = None,
        apply_at_callsite: bool = False,
    ):
        self._data.depends(
            dest, *sources, value=value, apply_at_callsite=apply_at_callsite
        )

    def save_closures(self):
        if self._closures is None:
            self._closures = self.get_closures()

    @property
    def cc(self):
        if self._data.cc is None:
            try:
                self._data.cc = CallingConventionResolver(
                    self.state.analysis.project,
                    self.state.arch,
                    self.state.analysis.project.kb.functions,
                ).get_cc(self._data.name)
            except KeyError:
                pass

        return self._data.cc

    def get_closures(self) -> Dict[Atom, Set[Definition]]:
        closures: Dict[Atom, Set[Definition]] = {}
        for atom in self.atoms:
            defs = {defn for defn in self.definitions if defn.atom == atom}
            closures[atom] = {
                defn
                for graph in transitive_closures_from_defs(
                    defs, self.state.dep_graph
                ).values()
                for defn in graph.nodes()
            }
        return closures

    def get_arg_vals(self):
        vals = {}
        for atom in [y for x in self.args_atoms for y in x]:
            value = self.state.live_definitions.get_value_from_atom(atom)
            if value is not None:
                vals[atom] = value
            else:
                vals[atom] = Utils.unknown_value_of_unknown_size(
                    self.state, atom, self._data.callsite_codeloc
                )
        return vals

    def tag_params(self, first_run=False):
        if self.state.arch.name.startswith("MIPS"):
            t9_reg = Register(*self.state.arch.registers["t9"], self.state.arch)
            t9_val = self.state.live_definitions.get_value_from_atom(t9_reg)
            self.depends(t9_reg, value=t9_val)

        if self.name.startswith("execl"):
            self._data.args_atoms = self._get_execl_vararg_atoms(self.state)
        elif any(
            x in self.function.name
            for x in ["printf", "scanf", "twsystem", "doSystemCmd", "execFormatCmd"]
        ):
            self._data.args_atoms = self._get_printf_vararg_atoms(self.state)

        for atom in self.atoms:
            self.state.add_use(atom)
            self.definitions |= set(self.state.get_definitions(atom))
            mv = self.state.live_definitions.get_value_from_atom(atom)
            if not self.ret_atoms or atom not in self.ret_atoms:
                self._data.depends(atom, value=mv, apply_at_callsite=True)
            self._arg_vals[atom] = mv or MultiValues(
                self.state.top(self.state.arch.bits)
            )
            if mv is None:
                self.constant_data[atom] = None
                continue

    def save_constant_arg_data(self, state):
        for defn in self.definitions:
            mv = self.state.live_definitions.get_value_from_definition(defn)
            atom = defn.atom
            if isinstance(atom, MemoryLocation) and isinstance(atom.addr, SpOffset):
                if -1 * atom.addr.offset >> 31 == 1:
                    real_offset = atom.addr.offset + 2**state.arch.bits
                    for x in self.atoms:
                        if isinstance(x, MemoryLocation) and isinstance(
                            x.addr, SpOffset
                        ):
                            if x.addr.offset == real_offset:
                                atom = x
                                break
            if atom not in self.atoms:
                for a in self.atoms:
                    if not isinstance(a, type(atom)):
                        continue

                    if isinstance(a, Register):
                        if a.reg_offset == atom.reg_offset:
                            atom = a
                            break
                    elif isinstance(a, MemoryLocation):
                        if a.addr == atom.addr:
                            atom = a
                            break

            if hasattr(atom, "endness") and atom.endness is None:
                atom.endness = self.state.arch.memory_endness
            try:
                self.constant_data[atom] = get_constant_data(defn, mv, state)
            except (AssertionError, AttributeError):
                self.constant_data[atom] = None

    def _get_function_code_loc(self):
        return CodeLocation(self.function.addr, 0, ins_addr=self.function.addr)

    def _get_execl_vararg_atoms(self, state: ReachingDefinitionsState):
        if self.function.calling_convention is None or self.function.prototype is None:
            return []

        atoms = []
        arg_session = self.function.calling_convention.arg_session(None)
        ty = self.function.prototype.args[0]
        for _ in range(10):
            arg = self.function.calling_convention.next_arg(
                arg_session, ty.with_arch(state.arch)
            )
            atom = cc_to_rd(arg, state.arch, state)
            val = Utils.get_values_from_cc_arg(arg, state, state.arch)
            one_val = val.one_value()
            if one_val is not None and one_val.concrete and one_val.concrete_value == 0:
                break
            atoms.append({atom})

        return atoms

    def _get_printf_vararg_atoms(self, state: ReachingDefinitionsState):
        if self.function.calling_convention is None or self.function.prototype is None:
            return []

        atoms = []
        arg_session = self.function.calling_convention.arg_session(None)
        for ty in self.function.prototype.args:
            arg = self.function.calling_convention.next_arg(
                arg_session, ty.with_arch(state.arch)
            )
            atoms.append({cc_to_rd(arg, state.arch, state)})

        fmt_ptrs = Utils.get_values_from_cc_arg(arg, state, state.arch)
        fmt_strs = Utils.get_strings_from_pointers(fmt_ptrs, state, self.code_loc)
        for fmt_str in [
            x for x in Utils.get_values_from_multivalues(fmt_strs) if x.concrete
        ]:
            for _ in Utils.get_prototypes_from_format_string(
                Utils.bytes_from_int(fmt_str)
            ):
                arg = self.function.calling_convention.next_arg(
                    arg_session, SimTypePointer(SimTypeChar()).with_arch(state.arch)
                )
                atoms.append({cc_to_rd(arg, state.arch, state)})

        return atoms

    def has_definition(self, definition: Definition) -> bool:
        return any(definition == defn for defn in self.definitions)

    def save_ret_value(self, value=None):
        for atom in self.ret_atoms:
            self._ret_val = value
            self.depends(atom, *self.atoms, value=value)
            if value is not None:
                self.return_definitions = set(
                    LiveDefinitions.extract_defs_from_mv(self._ret_val)
                )

    def save_constant_ret_data(self, new_state=None, value=None):
        state = new_state or self.state
        for atom in self.ret_atoms:
            for defn in LiveDefinitions.extract_defs_from_mv(value):
                if atom not in self.return_data:
                    self.return_data[atom] = []
                try:
                    if value is not None:
                        self.return_data[atom].extend(
                            get_constant_data(defn, value, state)
                        )
                    else:
                        self.return_data[atom].extend([None])
                except AssertionError:
                    self.return_data[atom].extend([None])

    def handle_ret(self, new_state=None, value=None):
        if not self.ret_atoms:
            return
        if (
            value is None
            and not self.function.is_simprocedure
            and not self.function.is_plt
        ):
            merged_values = None
            for atom in self.ret_atoms:
                if new_state:
                    state = new_state
                else:
                    state = self.state
                v = state.get_values(atom)
                if merged_values is None:
                    merged_values = v
                else:
                    merged_values = merged_values.merge(v)
            value = merged_values

        self.save_ret_value(value=value)

    @property
    def failed_tuple(self):
        return False, self.state, self.visited_blocks, self.state.dep_graph

    @property
    def success_tuple(self):
        return True, self.state, self.visited_blocks, self.state.dep_graph

    @property
    def func_tuple(self):
        return Utils.get_func_tuple(
            self.function, self.subject, self.state.arch, self.code_loc
        )

    @property
    def exit_site_addresses(self):
        return [f.addr for f in self.function.ret_sites + self.function.jumpout_sites]

    def __str__(self):
        return f"{self.function.name}({', '.join(str(self.arg_vals[y]) for x in self.args_atoms for y in x)}) @ {hex(self.code_loc.ins_addr or self.code_loc.block_addr)}"

    def __repr__(self):
        return self.__str__()

    def __hash__(self):
        if self._hash is None:
            # hash_args = []
            # for arg in {y for x in self.args_atoms for y in x}:
            #    for vals in self.arg_vals[arg].values():
            #        hash_args.extend(list(vals))
            # hash_args.extend(list(self.visited_blocks))
            # hash_args.append(self.code_loc.block_addr)
            # self._hash = hash(tuple(hash_args))
            self._hash = hash(tuple([str(self)] + list(self.call_stack)))
        return self._hash

    def __eq__(self, other):

        return hash(self) == hash(other)
