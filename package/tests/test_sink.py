from unittest import mock, TestCase

from angr.sim_type import SimTypeFunction, SimTypeInt

from argument_resolver.external_function import VULN_TYPES, Sink


class TestSink(TestCase):
    MOCK_LIBRARIES = {
        "a_sink": SimTypeFunction([SimTypeInt()], SimTypeInt(), arg_names=["key"]),
    }

    @mock.patch(
        "argument_resolver.external_function.CUSTOM_DECLS",
        MOCK_LIBRARIES,
    )
    def test_expose_list_of_command_injection_sinks(self):
        for f in VULN_TYPES["cmdi"]:
            self.assertEqual(type(f), Sink)

    @mock.patch(
        "argument_resolver.external_function.CUSTOM_DECLS",
        MOCK_LIBRARIES,
    )
    def test_a_sink_has_a_dictionary_of_vulnerable_parameters_specifying_their_positions_and_type(
        self,
    ):
        sink = Sink("a_sink", [1])
        vulnerable_parameters = [1]

        self.assertListEqual(sink.vulnerable_parameters, vulnerable_parameters)
