import logging
import os

from unittest import TestCase

from angr.knowledge_plugins.key_definitions.atoms import Register
from angr.calling_conventions import SimRegArg, SimStackArg, SimCC
from angr.engines.light import SpOffset
from archinfo import (
    ArchX86,
    ArchAMD64,
    ArchARM,
    ArchAArch64,
    ArchMIPS32,
    ArchMIPS64,
    ArchPPC32,
    ArchPPC64,
)

from argument_resolver.utils.calling_convention import (
    # CallingConventionResolver,
    cc_to_rd,
    get_default_cc_with_args,
)


BINARIES_DIR = os.path.realpath(
    os.path.join(
        os.path.realpath(__file__), "..", "..", "..", "..", "binaries", "tests"
    )
)
LOGGER = logging.getLogger("argument_resolver/test_calling_convention")


class TestCallingConvention(TestCase):
    def test_get_default_cc_with_args(self):
        def run_all_tests_for(arch):
            list(
                map(
                    lambda x: run_test(
                        arch["arch"], x[0], x[1], arch["expected_return_value"]
                    ),
                    zip(
                        arch["number_of_parameters"],
                        arch["expected_args"],
                    ),
                )
            )

        def run_test(arch, number_of_parameters, expected_args, expected_return_value):
            cc_with_args = get_default_cc_with_args(number_of_parameters, arch)

            computed_args = []
            int_args = cc_with_args.int_args
            mem_args = cc_with_args.memory_args
            while (x := next(int_args, None)) is not None and len(
                computed_args
            ) < number_of_parameters:
                computed_args.append(str(x))
            for _ in range(number_of_parameters - len(computed_args)):
                computed_args.append(str(next(mem_args)))
            computed_return_value = str(cc_with_args.RETURN_VAL)

            self.assertEqual(expected_args, computed_args)
            self.assertEqual(expected_return_value, computed_return_value)
            self.assertTrue(isinstance(cc_with_args, SimCC))

        # Create some data, which expected results are based on commit 2c195cb implementation's returns,
        # and throw the tests at them.
        data = [
            {
                "arch": ArchX86(),
                "number_of_parameters": [1, 3],
                "expected_args": [
                    ["[0x4]"],
                    ["[0x4]", "[0x8]", "[0xc]"],
                ],
                "expected_return_value": "<eax>",
            },
            {
                "arch": ArchAMD64(),
                "number_of_parameters": [1, 9],
                "expected_args": [
                    ["<rdi>"],
                    [
                        "<rdi>",
                        "<rsi>",
                        "<rdx>",
                        "<rcx>",
                        "<r8>",
                        "<r9>",
                        "[0x8]",
                        "[0x10]",
                        "[0x18]",
                    ],
                ],
                "expected_return_value": "<rax>",
            },
            {
                "arch": ArchARM(),
                "number_of_parameters": [1, 6],
                "expected_args": [
                    ["<r0>"],
                    ["<r0>", "<r1>", "<r2>", "<r3>", "[0x0]", "[0x4]"],
                ],
                "expected_return_value": "<r0>",
            },
            {
                "arch": ArchAArch64(),
                "number_of_parameters": [1, 6],
                "expected_args": [
                    ["<x0>"],
                    ["<x0>", "<x1>", "<x2>", "<x3>", "<x4>", "<x5>"],
                ],
                "expected_return_value": "<x0>",
            },
            {
                "arch": ArchMIPS32(),
                "number_of_parameters": [1, 6],
                "expected_args": [
                    ["<a0>"],
                    ["<a0>", "<a1>", "<a2>", "<a3>", "[0x10]", "[0x14]"],
                ],
                "expected_return_value": "<v0>",
            },
            {
                "arch": ArchMIPS64(),
                "number_of_parameters": [1, 6],
                "expected_args": [
                    ["<a0>"],
                    ["<a0>", "<a1>", "<a2>", "<a3>", "<a4>", "<a5>"],
                ],
                "expected_return_value": "<v0>",
            },
            {
                "arch": ArchPPC32(),
                "number_of_parameters": [1, 10],
                "expected_args": [
                    ["<r3>"],
                    [
                        "<r3>",
                        "<r4>",
                        "<r5>",
                        "<r6>",
                        "<r7>",
                        "<r8>",
                        "<r9>",
                        "<r10>",
                        "[0x8]",
                        "[0xc]",
                    ],
                ],
                "expected_return_value": "<r3>",
            },
            {
                "arch": ArchPPC64(),
                "number_of_parameters": [1, 10],
                "expected_args": [
                    ["<r3>"],
                    [
                        "<r3>",
                        "<r4>",
                        "<r5>",
                        "<r6>",
                        "<r7>",
                        "<r8>",
                        "<r9>",
                        "<r10>",
                        "[0x70]",
                        "[0x78]",
                    ],
                ],
                "expected_return_value": "<r3>",
            },
        ]

        list(map(run_all_tests_for, data))

    # def test_get_cc_with_known_external_function(self):
    #    @mock.patch("argument_resolver.calling_convention.get_default_cc_with_args")
    #    def run_test_for_external_function(
    #        project,
    #        function,
    #        expected_number_of_arguments,
    #        mock_get_default_cc_with_args,
    #    ):
    #        calling_convention_resolver = CallingConventionResolver(
    #            project, project.arch, None
    #        )
    #        _ = calling_convention_resolver.get_cc(function)

    #        # Just test proper delegation to `get_default_cc_with_args()` as it has been thoroughly tested
    #        mock_get_default_cc_with_args.assert_called_once_with(
    #            expected_number_of_arguments, project.arch
    #        )

    #    def run_test_for_arch(arch_and_binary):
    #        functions = [
    #            {"name": "system", "expected_number_of_arguments": 1},
    #            {"name": "popen", "expected_number_of_arguments": 2},
    #            {"name": "printf", "expected_number_of_arguments": 1},
    #            {"name": "strcmp", "expected_number_of_arguments": 2},
    #            {"name": "strncmp", "expected_number_of_arguments": 3},
    #            {"name": "strcasecmp", "expected_number_of_arguments": 2},
    #            {"name": "strncasecmp", "expected_number_of_arguments": 3},
    #            {"name": "strcoll", "expected_number_of_arguments": 2},
    #            {"name": "strcpy", "expected_number_of_arguments": 2},
    #            {"name": "strncpy", "expected_number_of_arguments": 3},
    #            {"name": "strcat", "expected_number_of_arguments": 2},
    #            {"name": "strncat", "expected_number_of_arguments": 3},
    #            {"name": "sprintf", "expected_number_of_arguments": 2},
    #            {"name": "snprintf", "expected_number_of_arguments": 3},
    #            {"name": "atoi", "expected_number_of_arguments": 1},
    #            {"name": "nvram_set", "expected_number_of_arguments": 2},
    #            {"name": "acosNvramConfig_set", "expected_number_of_arguments": 2},
    #            {"name": "nvram_get", "expected_number_of_arguments": 1},
    #            {"name": "nvram_safe_get", "expected_number_of_arguments": 1},
    #            {"name": "acosNvramConfig_get", "expected_number_of_arguments": 1},
    #            {"name": "malloc", "expected_number_of_arguments": 1},
    #            {"name": "calloc", "expected_number_of_arguments": 2},
    #            {"name": "read", "expected_number_of_arguments": 3},
    #            {"name": "fgets", "expected_number_of_arguments": 3},
    #        ]

    #        arch = arch_and_binary[0]
    #        binary = arch_and_binary[1]

    #        # If arch is one of the PPC ones, do not specify it in the `Project` constructor, to avoid
    #        # https://github.com/angr/angr/issues/1553 .
    #        def is_ppc(arch):
    #            return arch.name.find("ppc") > -1

    #        project = Project(binary, arch=arch) if is_ppc(arch) else Project(binary)

    #        list(
    #            map(
    #                lambda x: run_test_for_external_function( # pylint: disable=[no-value-for-parameter]
    #                    project, x["name"], x["expected_number_of_arguments"]
    #                ),
    #                functions,
    #            )
    #        )

    #    arches = [
    #        ArchX86(),
    #        ArchAMD64(),
    #        ArchARM(),
    #        ArchAArch64(),
    #        ArchMIPS32(),
    #        ArchMIPS64(),
    #        ArchPPC32(),
    #        ArchPPC64(),
    #    ]
    #    binaries = list(
    #        map(
    #            lambda binary: os.path.join(BINARIES_DIR, binary),
    #            [
    #                "i386/fauxware",
    #                "x86_64/fauxware",
    #                "android/arm/fauxware",
    #                "android/aarch64/fauxware",
    #                "mips/fauxware",
    #                "mips64/ld.so.1",
    #                "ppc/fauxware",
    #                "ppc64/fauxware",
    #            ],
    #        )
    #    )
    #    list(map(run_test_for_arch, zip(arches, binaries)))

    # @mock.patch.object(logging.Logger, "error")
    # def test_get_cc_with_a_function_not_in_CFG(self, mock_Logger_error):
    #    MockFunctions = {}

    #    arch = ArchX86()
    #    project = Project(os.path.join(BINARIES_DIR, "i386/fauxware"), arch=arch)

    #    calling_convention_resolver = CallingConventionResolver(
    #        project, arch, MockFunctions # pylint: disable=[undefined-variable]
    #    )

    #    function_name = "unknown"
    #    _ = calling_convention_resolver.get_cc(function_name)

    #    mock_Logger_error.assert_called_once_with(
    #        "CCA: Failed for %s(), function neither an external function nor have its name in CFG",
    #        function_name,
    #    )

    def test_cc_to_rd_return_a_stack_pointer_offset_when_given_a_SimStackArg(self):
        arch = ArchX86()
        sim = SimStackArg(0x42, 1)
        result = cc_to_rd(sim, arch)

        # See angr/angr/engines/light/data.py for `SpOffset` formatting
        self.assertEqual(str(result.addr), "SP+0x42")
        self.assertEqual(result.addr.__class__, SpOffset)

    def test_cc_to_rd_return_a_register_when_given_a_SimRegArg(self):
        arch = ArchX86()
        sim = SimRegArg("esp", 1)
        result = cc_to_rd(sim, arch)

        # See angr/angr/analyses/reaching_definitions/atoms.py for `Register` formatting
        self.assertEqual(str(result), "<Reg esp<4>>")
        self.assertEqual(result.__class__, Register)

    def test_cc_to_rd_with_a_parameter_of_the_wrong_type(self):
        arch = ArchX86()
        param = "This is a string so that won't work."

        self.assertRaises(TypeError, cc_to_rd, param, arch)
