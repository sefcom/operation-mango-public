from handler_tester import HandlerTester

from angr.knowledge_plugins.key_definitions.constants import OP_AFTER
from angr.analyses.reaching_definitions.dep_graph import DepGraph

from argument_resolver.handlers import handler_factory, StdioHandlers
from argument_resolver.utils.utils import Utils

from archinfo import Endness


class TestStdioHandlers(HandlerTester):
    TESTED_HANDLER = handler_factory([StdioHandlers])

    def test_handle_sprintf(self):
        string = "Hello World!"
        program = f"""
            #include <stdio.h>
            void main() {{
                char greeting[0x40];
                sprintf(greeting, "Greeting: %s", "{string}");
            }}
        """
        final_output = "Greeting: " + string
        project = self.project_and_cfg_analysis_from(program)

        handler = self.TESTED_HANDLER(project, False)

        sprintf = project.kb.functions.function(name="sprintf")
        observation_points = set(Utils.get_all_callsites(project))
        subject = self.subject_from_function(project, sprintf)

        rda = self.RDA(
            subject=subject,
            observation_points=observation_points,
            function_handler=handler,
            dep_graph=DepGraph(),
        )

        results = handler.analyzed_list[-1].state
        cc = project.analyses.CallingConvention(sprintf).cc
        args = cc.int_args

        arg_dst = next(args)

        dst_values = Utils.get_values_from_cc_arg(
            arg_dst,
            results,
            rda.project.arch,
        )

        printed_str = Utils.get_strings_from_pointers(dst_values, results, None)

        self.assertEqual(
            Utils.bytes_from_int(printed_str.one_value()).decode("utf-8"),
            final_output,
        )

    def test_handle_sprintf_unknown_string(self):
        string = "Greeting: "
        format_string = "%s"
        program = f"""
            #include <stdio.h>
            void main(int argc, char **argv) {{
                char greeting[0x40];
                sprintf(greeting, "{string + format_string}", argv[1]);
            }}
        """
        project = self.project_and_cfg_analysis_from(program)

        handler = self.TESTED_HANDLER(project, False)

        sprintf = project.kb.functions.function(name="sprintf")
        observation_points = set(Utils.get_all_callsites(project))
        subject = self.subject_from_function(project, sprintf)

        rda = self.RDA(
            subject=subject,
            observation_points=observation_points,
            function_handler=handler,
            dep_graph=DepGraph(),
        )

        results = handler.analyzed_list[-1].state
        cc = project.analyses.CallingConvention(sprintf).cc
        args = cc.int_args
        arg_dst = next(args)

        dst_values = Utils.get_values_from_cc_arg(
            arg_dst,
            results,
            rda.project.arch,
        )

        printed_str = Utils.get_strings_from_pointers(dst_values, results, None)

        self.assertEqual(
            Utils.bytes_from_int(
                printed_str.one_value()[: results.arch.bytes * 8]
            ).decode("utf-8"),
            string,
        )
        self.assertTrue(
            results.is_top(printed_str.one_value()[(results.arch.bytes * 8) - 1 :])
        )
