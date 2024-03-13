import claripy
import logging

from unittest import TestCase

from archinfo import ArchAMD64
from angr.calling_conventions import SimStackArg

from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation, Register
from angr.code_location import CodeLocation
from angr.analyses.reaching_definitions.reaching_definitions import LiveDefinitions

from argument_resolver.utils.utils import Utils

LOGGER = logging.getLogger("argument_resolver/test_utils")


def _write(string, memory, at_address):
    i = 0
    for char in string:
        memory[at_address + i] = char
        i += 1


class TestUtils(TestCase):
    def test_get_values_from_cc_arg_with_sp_offset(self):
        arch = ArchAMD64()
        reach_def = LiveDefinitions(arch=arch)

        sp = Register(arch.sp_offset, arch.bytes)
        sp_offset = reach_def.stack_address(arch.sp_offset)

        # Assume argument is located 4 words away from the stack pointer,
        # and has some arbitrary value.
        arg_stack_offset = 4
        arbitrary_value = 0

        # Segment of memory to represent a portion of the stack containing our parameter.
        ml = MemoryLocation(sp_offset + arg_stack_offset, arch.bytes)
        ml_value = MultiValues(
            offset_to_values={0: {claripy.BVV(arbitrary_value, arch.bits)}}
        )

        # We need to setup two components in the `LiveDefinitions`:
        #   - the `sp` register value to make offset computations possible;
        #   - the portion of the stack containing our parameter.
        reach_def.registers.store(sp.reg_offset, sp_offset, sp.size)
        reach_def.stack.store(
            reach_def.get_stack_address(ml.addr), ml_value, ml.size
        )

        definitions = Utils.get_values_from_cc_arg(
            SimStackArg(arg_stack_offset, arch.bytes), reach_def, arch
        )

        self.assertEqual(definitions.one_value()._model_concrete.value, 0x0)

    def test_get_values_from_cc_arg_with_invalid_first_arg(self):
        with self.assertRaises(TypeError) as cm:
            Utils.get_values_from_cc_arg([], None, None)

        ex = cm.exception
        self.assertEqual(str(ex), "Expected SimRegArg or SimStackArg, got list")

    def test_get_prototypes_from_format_string(self):
        prototypes = Utils.get_prototypes_from_format_string(
            "foo: %s, bar: %#x, baz: %10i"
        )

        self.assertEqual(prototypes[0].prototype, "%s")
        self.assertEqual(prototypes[0].specifier, "s")
        self.assertEqual(prototypes[0].position, 5)

        self.assertEqual(prototypes[1].prototype, "%#x")
        self.assertEqual(prototypes[1].specifier, "x")
        self.assertEqual(prototypes[1].position, 14)

        self.assertEqual(prototypes[2].prototype, "%10i")
        self.assertEqual(prototypes[2].specifier, "i")
        self.assertEqual(prototypes[2].position, 24)

    def test_is_stack_address(self):
        base = claripy.BVS("stack_base", 64, explicit_name=True)
        offset = 0xBEEF
        base += offset

        not_base = claripy.BVS("TOP", 64, explicit_name=True)

        self.assertTrue(Utils.is_stack_address(base))
        self.assertFalse(Utils.is_stack_address(not_base))

    def test_bytes_from_int(self):
        string = b"Hello World!"
        byte_string = claripy.BVV(string, len(string) * 8)

        result = Utils.bytes_from_int(byte_string)
        self.assertTrue(result == string)

    def test_get_strings_from_pointer_concrete_memory_address(self):
        arch = ArchAMD64()
        reach_def = LiveDefinitions(arch=arch)
        string = b"Hello World!"

        sp = Register(arch.sp_offset, arch.bytes)
        sp_offset = reach_def.stack_address(arch.sp_offset)

        reach_def.registers.store(sp.reg_offset, sp_offset, sp.size)

        mem_loc = MemoryLocation(claripy.BVV(0x40000, arch.bits), len(string))
        code_loc = CodeLocation(0, 0)
        concrete_mv = MultiValues(
            offset_to_values={0: {claripy.BVV(string, len(string) * 8)}}
        )

        reach_def.kill_and_add_definition(mem_loc, code_loc, concrete_mv)

        strings = Utils.get_strings_from_pointer(mem_loc.addr, reach_def, code_loc)
        self.assertEqual(Utils.bytes_from_int(strings.one_value()), string)

    def test_get_strings_from_pointer_concrete_stack_address(self):
        arch = ArchAMD64()
        reach_def = LiveDefinitions(arch=arch)
        string = b"Hello World!"

        sp = Register(arch.sp_offset, arch.bytes)
        sp_offset = reach_def.stack_address(arch.sp_offset)

        reach_def.registers.store(sp.reg_offset, sp_offset, sp.size)

        mem_loc = MemoryLocation(
            claripy.BVV(reach_def.get_stack_address(sp_offset), arch.bits), len(string)
        )
        code_loc = CodeLocation(0, 0)
        concrete_mv = MultiValues(
            offset_to_values={0: {claripy.BVV(string, len(string) * 8)}}
        )

        reach_def.kill_and_add_definition(mem_loc, code_loc, concrete_mv)

        strings = Utils.get_strings_from_pointer(mem_loc.addr, reach_def, code_loc)
        self.assertEqual(Utils.bytes_from_int(strings.one_value()), string)

    def test_get_strings_from_pointer_symbolic_stack_address(self):
        arch = ArchAMD64()
        reach_def = LiveDefinitions(arch=arch)
        string = b"Hello World!"

        sp = Register(arch.sp_offset, arch.bytes)
        sp_offset = reach_def.stack_address(arch.sp_offset)

        reach_def.registers.store(sp.reg_offset, sp_offset, sp.size)

        mem_loc = MemoryLocation(sp_offset, len(string))
        code_loc = CodeLocation(0, 0)
        concrete_mv = MultiValues(
            offset_to_values={0: {claripy.BVV(string, len(string) * 8)}}
        )

        reach_def.kill_and_add_definition(mem_loc, code_loc, concrete_mv)

        strings = Utils.get_strings_from_pointer(mem_loc.addr, reach_def, code_loc)
        self.assertEqual(Utils.bytes_from_int(strings.one_value()), string)

    def test_get_strings_from_pointer_unknown_address(self):
        arch = ArchAMD64()
        reach_def = LiveDefinitions(arch=arch)
        string = b"Hello World!"

        sp = Register(arch.sp_offset, arch.bytes)
        sp_offset = reach_def.stack_address(arch.sp_offset)

        reach_def.registers.store(sp.reg_offset, sp_offset, sp.size)

        mem_loc = MemoryLocation(reach_def.top(arch.bits), len(string))
        code_loc = CodeLocation(0, 0)
        concrete_mv = MultiValues(
            offset_to_values={0: {claripy.BVV(string, len(string) * 8)}}
        )

        reach_def.kill_and_add_definition(mem_loc, code_loc, concrete_mv)

        strings = Utils.get_strings_from_pointer(mem_loc.addr, reach_def, code_loc)
        self.assertTrue(reach_def.is_top(strings.one_value()))

    def test_get_values_from_multivalues(self):
        values = MultiValues(
            offset_to_values={
                0: {claripy.BVV(0x0, 8), claripy.BVV(0x1, 8)},
                8: {claripy.BVV(0x2, 8)},
            }
        )
        all_vals = Utils.get_values_from_multivalues(values)
        self.assertEqual(
            sorted([2, 258]), sorted([x._model_concrete.value for x in all_vals])
        )

    def test_get_size_from_multivalues(self):
        string = "Hello World!"
        values = MultiValues(
            offset_to_values={
                0: {claripy.BVV(string[: len(string) // 2], len(string) // 2 * 8)},
                6: {claripy.BVV(string[len(string) // 2 :], len(string) // 2 * 8)},
            }
        )
        size = Utils.get_size_from_multivalue(values)
        self.assertEqual(size, len(string))

    def test_strip_null_from_string(self):
        string = "Hello World!\x00"
        value = claripy.BVV(string, len(string) * 8)
        self.assertTrue(value[7:]._model_concrete.value == 0)
