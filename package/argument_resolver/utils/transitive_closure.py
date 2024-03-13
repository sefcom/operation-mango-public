from typing import Dict, Iterable, Set, TYPE_CHECKING

import networkx
import claripy

from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions
from angr.code_location import ExternalCodeLocation
from angr.analyses.reaching_definitions.reaching_definitions import ReachingDefinitionsAnalysis
from angr.analyses.reaching_definitions.reaching_definitions import ReachingDefinitionsState
from angr.engines.light import SpOffset
from angr.knowledge_plugins.cfg import CFGNode
from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation, Register

from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.errors import SimMemoryMissingError

from .utils import Utils


def transitive_closures_from_defs(
    vulnerable_defs: Iterable[Definition], dep_graph: "DepGraph"
) -> Dict[Definition, networkx.DiGraph]:
    """
    Determine the transitive closure of a single atom in the dependency graph of a given <ReachingDefinitionsAnalysis>
    (computed for a given sink).

    :param vulnerable_atom: The vulnerable_atom to compute the transitive closure of in the dependency graph.
    :param rda: The ReachingDefinitionsAnalysis that computed the dependency graph to get the transitive closure from.
    :return: A dictionary where sink-caller nodes are keys, and related transitive closure are values.
    """

    closures = {}
    for defn in vulnerable_defs:
        closure = dep_graph.transitive_closure(defn)
        if len(closure) > 0:
            closures[defn] = closure

    return closures


def contains_an_external_definition(
    transitive_closures: Dict[Definition, Set["Closure"]]
) -> bool:
    """
    Determine if there is any values in the closure are marked as coming from External;
    These values are not resolved.

    *Note* This is lazily evaluated.
    """
    any_node_is_external = lambda nodes: any(
        isinstance(node.codeloc, ExternalCodeLocation) for node in nodes
    )
    return any(
        any_node_is_external(closure.rda.dep_graph.nodes())
        for s in transitive_closures.values() for closure in s
    )


def represents_constant_data(
    definition: Definition,
    values: MultiValues,
    livedef: "LiveDefinitions",
) -> bool:
    """
    Tell if a <Definition> is completely resolved to a constant value, or not (might be influenced by external factors).

    :param definition: The definition to consider.
    :param values: The pair of all definitions and values.
    :param livedef: LiveDefinition pertaining to the original definition.
    :param dependency_graph: The transitive closure containing

    :return: `True` if the definition represents constant data, `False` otherwise.
    """
    data = get_constant_data(definition, values, livedef)
    if data is None or any(d is None for d in data):
        return False
    else:
        return True


def get_constant_data(
    definition: Definition,
    values: MultiValues,
    livedef: ReachingDefinitionsState,
) -> list:
    """
    Tell if a <Definition> is completely resolved to a constant value, or not (might be influenced by external factors).

    :param definition: The definition to consider.
    :param values: The pair of all definitions and values.
    :param livedef: LiveDefinition pertaining to the original definition.
    :param dependency_graph: The transitive closure containing

    :return: `True` if the definition represents constant data, `False` otherwise.
    """
    if isinstance(definition.atom, MemoryLocation):

        def _is_concrete(datum):
            if datum.concrete:
                addr = datum._model_concrete.value
                try:
                    mv = livedef.heap.load(addr, definition.atom.size, endness=livedef.arch.memory_endness)
                except SimMemoryMissingError:
                    try:
                        mv = livedef.memory.load(addr, definition.atom.size, endness=livedef.arch.memory_endness)
                    except SimMemoryMissingError:
                        mv = MultiValues(offset_to_values={0: {datum}})
            elif livedef.is_stack_address(datum):
                try:
                    if datum.op == "Reverse":
                        datum = datum.args[0]
                    if livedef.get_stack_address(datum) is None:
                        return [None]
                    endness = livedef.arch.memory_endness
                    mv = livedef.stack.load(
                        livedef.get_stack_address(datum),
                        definition.atom.size,
                        endness=endness,
                    )
                except SimMemoryMissingError:
                    return [None]
            else:
                return [None]

            values = Utils.get_values_from_multivalues(mv)
            if not all(isinstance(val, claripy.ast.Base) and val.concrete for val in values):
                return [None]

            return values

        vals = [_is_concrete(v) for vals in values.values() for v in vals]
        return [y for x in vals for y in x]

    elif isinstance(definition.atom, Register):
        pointed_addresses = Utils.get_values_from_multivalues(values)

        data_all_concrete = all(
            isinstance(v, (int, SpOffset))
            or (
                isinstance(v, claripy.ast.Base)
                and (Utils.is_stack_address(v) or v.concrete or Utils.is_heap_address(v))
            )
            for v in pointed_addresses
        )
        if not data_all_concrete:
            return [None]

        new_mv = MultiValues()
        concrete_vals = []
        for offset, vals in values.items():
            for val in vals:
                try:
                    sp = livedef.get_sp()
                except AssertionError:
                    sp = livedef.arch.initial_sp
                if isinstance(livedef, LiveDefinitions):
                    proj = livedef.project
                else:
                    proj = livedef.analysis.project
                if val.concrete and proj is not None and not Utils.is_pointer(val, sp, proj):
                    concrete_vals.append(val)
                else:
                    new_mv.add_value(offset, val)

        strings = Utils.get_strings_from_pointers(
            new_mv, livedef, definition.codeloc
        )
        values = [y for x in strings.values() for y in x]
        if all(x.concrete for x in values):
            return values + concrete_vals
        return [None]

    else:
        message = f"The case where the given definition's atom is of type {definition.atom} has not been handled!"
        raise NotImplementedError(message)
