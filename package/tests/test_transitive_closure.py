import claripy
import logging
import networkx

from unittest import TestCase

from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation, Register
from angr.code_location import CodeLocation
from angr.analyses.reaching_definitions.reaching_definitions import LiveDefinitions
from angr.code_location import ExternalCodeLocation
from angr.analyses.reaching_definitions.dep_graph import DepGraph

from archinfo import ArchAMD64
from argument_resolver.utils.transitive_closure import (
    contains_an_external_definition,
    represents_constant_data,
)
from argument_resolver.utils.closure import Closure

LOGGER = logging.getLogger("argument_resolver/test_utils")


def _init_reach_def():
    arch = ArchAMD64()
    reach_def = LiveDefinitions(arch=arch)

    sp = Register(arch.sp_offset, arch.bytes)
    sp_offset = reach_def.stack_address(arch.sp_offset)

    reach_def.registers.store(sp.reg_offset, sp_offset, sp.size)
    return reach_def


class TestTransitiveClosure(TestCase):
    STRING_IN_MEMORY = "some string of data in memory"
    STRING_IN_MEMORY_LENGTH = len(STRING_IN_MEMORY + "\x00")

    class ArchMock:
        def __init__(self):
            pass

        @property
        def bits(self):
            return 4

    class CFGMock:
        def __init__(self, memory_data):
            self._memory_data = memory_data

        @property
        def memory_data(self):
            return self._memory_data

    class MemoryDataMock:
        def __init__(self, address, content, size, sort):
            self._address = address
            self._content = content
            self._size = size
            self._sort = sort

        @property
        def address(self):
            return self._address

        @property
        def content(self):
            return self._content

        @property
        def size(self):
            return self._size

        @property
        def sort(self):
            return self._sort

    def test_contains_an_external_definition_return_false_when_all_definitions_are_local(
        self,
    ):
        local_definitions = list(
            map(lambda i: Definition(Register(i * 4, 4), CodeLocation(i, 0)), range(4))
        )

        # Create the following dependency graph:
        # R0 -> R1 -> R2 -> R3
        dependencies_graph = networkx.DiGraph(
            [
                (local_definitions[0], local_definitions[1]),
                (local_definitions[1], local_definitions[2]),
                (local_definitions[2], local_definitions[3]),
            ]
        )

        class A:
            dep_graph = DepGraph(dependencies_graph)

        transitive_closures = {0:  {Closure(None, A(), None)}}

        self.assertFalse(contains_an_external_definition(transitive_closures))

    def test_contains_an_external_definition_return_true_when_at_least_one_definition_is_external(
        self,
    ):
        external_definition = Definition(Register(0, 4), ExternalCodeLocation())
        local_definitions = list(
            map(
                lambda i: Definition(Register(i * 4, 4), CodeLocation(i, 0)),
                range(1, 4),
            )
        )

        # Create the following dependency graph:
        # R0 (external) -> R1 -> R2 -> R3
        dependencies_graph = networkx.DiGraph(
            [
                (external_definition, local_definitions[0]),
                (local_definitions[0], local_definitions[1]),
                (local_definitions[1], local_definitions[2]),
            ]
        )

        class A:
            dep_graph = DepGraph(dependencies_graph)
        transitive_closures = {0: {Closure(None, A(), None)}}

        self.assertTrue(contains_an_external_definition(transitive_closures))

    #def test_represents_constant_data_fails_if_definition_is_not_in_dependency_graph(
    #    self,
    #):
    #    reach_def = _init_reach_def()
    #    reg = Register(0, 4)
    #    codeloc = CodeLocation(0, 0)
    #    definition = Definition(reg, codeloc)
    #    values = MultiValues(offset_to_values={0: {claripy.BVV(0, 4 * 8)}})
    #    reach_def.kill_and_add_definition(reg, codeloc, values)

    #    dependency_graph = networkx.DiGraph()

    #    with self.assertRaises(AssertionError) as cm:
    #        represents_constant_data(definition, values, reach_def, dependency_graph)

    #    ex = cm.exception
    #    self.assertEqual(
    #        str(ex), "The given Definition must be present in the given graph."
    #    )

    def test_represents_constant_data_returns_True_if_definition_is_a_memory_location_and_its_data_is_a_string(
        self,
    ):
        reach_def = _init_reach_def()
        memloc = MemoryLocation(0x42, len(self.STRING_IN_MEMORY))
        codeloc = CodeLocation(0, 0)
        definition = Definition(memloc, codeloc)

        values = MultiValues(
            offset_to_values={
                0: {claripy.BVV(self.STRING_IN_MEMORY, len(self.STRING_IN_MEMORY) * 8)}
            }
        )
        reach_def.kill_and_add_definition(memloc, codeloc, values)

        dependency_graph = networkx.DiGraph()
        dependency_graph.add_node(definition)

        self.assertTrue(
            represents_constant_data(definition, values, reach_def)
        )

    def test_represents_constant_data_returns_False_if_definition_is_a_memory_location_and_its_data_contains_undefined(
        self,
    ):
        reach_def = _init_reach_def()
        memloc = MemoryLocation(0x42, len(self.STRING_IN_MEMORY))
        codeloc = CodeLocation(0, 0)
        definition = Definition(memloc, codeloc)
        values = MultiValues(
            offset_to_values={
                0: {
                    claripy.BVV(self.STRING_IN_MEMORY, len(self.STRING_IN_MEMORY) * 8),
                    claripy.BVS(
                        "TOP", len(self.STRING_IN_MEMORY) * 8, explicit_name=True
                    ),
                }
            }
        )
        reach_def.kill_and_add_definition(memloc, codeloc, values)

        dependency_graph = networkx.DiGraph()
        dependency_graph.add_node(definition)
        self.assertFalse(
            represents_constant_data(definition, values, reach_def)
        )

    def test_represents_constant_data_returns_True_if_definition_is_a_memory_location_and_its_data_is_an_integer(
        self,
    ):
        reach_def = _init_reach_def()
        memloc = MemoryLocation(0x42, 1)
        codeloc = CodeLocation(0, 0)
        definition = Definition(memloc, codeloc)

        values = MultiValues(offset_to_values={0: {claripy.BVV(0x84, 8)}})
        reach_def.kill_and_add_definition(memloc, codeloc, values)

        dependency_graph = networkx.DiGraph()
        dependency_graph.add_node(definition)

        self.assertTrue(
            represents_constant_data(definition, values, reach_def)
        )

    def test_represents_constant_data_returns_True_if_definition_is_a_memory_location_and_its_data_is_a_concat_completely_resolved(
        self,
    ):
        reach_def = _init_reach_def()
        memloc = MemoryLocation(0x42, 8)
        codeloc = CodeLocation(0, 0)
        definition = Definition(memloc, codeloc)

        values = MultiValues(
            offset_to_values={
                0: {claripy.BVV("cons", 8 * 4)},
                4: {claripy.BVV("tant", 8 * 4)},
            }
        )
        reach_def.kill_and_add_definition(memloc, codeloc, values)

        dependency_graph = networkx.DiGraph()
        dependency_graph.add_node(definition)
        self.assertTrue(
            represents_constant_data(definition, values, reach_def)
        )

    def test_represents_constant_data_returns_False_if_definition_is_a_memory_location_and_its_data_is_a_concat_containing_undefined(
        self,
    ):
        reach_def = _init_reach_def()
        memloc = MemoryLocation(0x42, 9)
        codeloc = CodeLocation(0, 0)
        definition = Definition(memloc, codeloc)

        values = MultiValues(
            offset_to_values={
                0: {reach_def.top(8)},
                1: {claripy.BVV("constant", 8 * 8)},
            }
        )
        reach_def.kill_and_add_definition(memloc, codeloc, values)

        dependency_graph = networkx.DiGraph()
        dependency_graph.add_node(definition)

        self.assertFalse(
            represents_constant_data(definition, values, reach_def)
        )

    def test_represents_constant_data_returns_True_when_it_is_a_register_that_is_a_memory_address_pointing_to_a_constant_string(
        self,
    ):
        reach_def = _init_reach_def()
        mem_address = 0x42
        memloc = MemoryLocation(mem_address, 8)
        codeloc = CodeLocation(0, 0)
        mem_loc_definition = Definition(memloc, codeloc)

        values = MultiValues(claripy.BVV("constant", 8 * 8))
        reach_def.kill_and_add_definition(memloc, codeloc, values)

        reg = Register(0, reach_def.arch.bits // 8)
        codeloc = CodeLocation(10, 0)
        reg_definition = Definition(reg, codeloc)

        values = MultiValues(claripy.BVV(mem_address, reach_def.arch.bits))
        reach_def.kill_and_add_definition(reg, codeloc, values)

        dependency_graph = networkx.DiGraph([(mem_loc_definition, reg_definition)])

        self.assertTrue(
            represents_constant_data(
                reg_definition, values, reach_def
            )
        )

    def test_represents_constant_data_returns_True_when_it_is_a_register_that_is_a_stack_offset_pointing_to_a_constant_string(
        self,
    ):
        reach_def = _init_reach_def()
        sp_offset = reach_def.stack_address(0x8)
        sp_offset_loc = MemoryLocation(sp_offset, len(self.STRING_IN_MEMORY))
        codeloc = CodeLocation(0, 0)
        sp_offset_definition = Definition(sp_offset_loc, codeloc)

        values = MultiValues(
            offset_to_values={
                0: {claripy.BVV(self.STRING_IN_MEMORY, len(self.STRING_IN_MEMORY) * 8)}
            }
        )
        reach_def.kill_and_add_definition(sp_offset_loc, codeloc, values)

        reg = Register(0, reach_def.arch.bytes)
        codeloc = CodeLocation(10, 0)
        register_definition = Definition(reg, codeloc)

        values = MultiValues(offset_to_values={0: {sp_offset}})
        reach_def.kill_and_add_definition(reg, codeloc, values)

        dependency_graph = networkx.DiGraph(
            [(sp_offset_definition, register_definition)]
        )

        self.assertTrue(
            represents_constant_data(
                register_definition, values, reach_def
            )
        )

    def test_represents_constant_data_returns_False_when_it_is_a_register_taking_at_least_an_unknown_value(
        self,
    ):
        reach_def = _init_reach_def()
        memory_address = 0x42
        memloc = MemoryLocation(memory_address, len(self.STRING_IN_MEMORY))
        codeloc = CodeLocation(0, 0)
        memory_location_definition = Definition(memloc, codeloc)

        values = MultiValues(
            offset_to_values={
                0: {claripy.BVV(self.STRING_IN_MEMORY, len(self.STRING_IN_MEMORY) * 8)}
            }
        )
        reach_def.kill_and_add_definition(memloc, codeloc, values)

        reg = Register(0, reach_def.arch.bytes)
        codeloc = CodeLocation(10, 0)
        register_definition = Definition(reg, codeloc)

        values = MultiValues(
            offset_to_values={
                0: {
                    claripy.BVV(memory_address, reach_def.arch.bits),
                    reach_def.top(reach_def.arch.bits),
                }
            }
        )
        reach_def.kill_and_add_definition(reg, codeloc, values)

        self.assertFalse(
            represents_constant_data(
                register_definition, values, reach_def
            )
        )

    def test_represents_constant_data_returns_False_when_it_is_a_register_that_can_take_memory_address_not_defined_earlier(
        self,
    ):
        reach_def = _init_reach_def()
        reg = Register(0, reach_def.arch.bytes)
        codeloc = CodeLocation(10, 0)
        register_definition = Definition(reg, codeloc)

        values = MultiValues(
            offset_to_values={0: {claripy.BVV(0xBEEF, reach_def.arch.bits)}}
        )
        reach_def.kill_and_add_definition(reg, codeloc, values)

        dependency_graph = networkx.DiGraph()
        dependency_graph.add_node(register_definition)

        self.assertFalse(
            represents_constant_data(
                register_definition, values, reach_def
            )
        )

    def test_represents_constant_data_returns_False_when_it_is_a_register_that_can_take_sp_offset_not_defined_earlier(
        self,
    ):
        reach_def = _init_reach_def()
        reg = Register(0, reach_def.arch.bytes)
        codeloc = CodeLocation(10, 0)
        register_definition = Definition(reg, codeloc)

        values = MultiValues(offset_to_values={0: {reach_def.stack_address(0x4)}})
        reach_def.kill_and_add_definition(reg, codeloc, values)

        dependency_graph = networkx.DiGraph()
        dependency_graph.add_node(register_definition)

        self.assertFalse(
            represents_constant_data(
                register_definition, values, reach_def
            )
        )
