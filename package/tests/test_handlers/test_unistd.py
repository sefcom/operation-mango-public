from handler_tester import HandlerTester

from angr.knowledge_plugins.key_definitions.atoms import Register
from angr.analyses.reaching_definitions.dep_graph import DepGraph

from argument_resolver.handlers import handler_factory, UnistdHandlers
from argument_resolver.utils.utils import Utils


class TestStdioHandlers(HandlerTester):
    TESTED_HANDLER = handler_factory([UnistdHandlers])

    def test_handle_read(self):
        read_size = 0x40
        program = f"""
            #include <stdio.h>
            void main() {{
                char greeting[{read_size}];
                read(0, greeting, {read_size});
            }}
        """
        project = self.project_and_cfg_analysis_from(program)

        read = project.kb.functions.function(name="read")
        subject = self.subject_from_function(project, read)
        observation_points = set(Utils.get_all_callsites(project))

        handler = self.TESTED_HANDLER(
            project, read, [Register(*project.arch.registers["rsi"])]
        )

        rda = self.RDA(
            subject=subject,
            observation_points=observation_points,
            function_handler=handler,
            dep_graph=DepGraph(),
        )

        cc = project.analyses.CallingConvention(read).cc
        args = cc.int_args
        next(args)
        arg_dst = next(args)

        state = handler.analyzed_list[-1].state
        dst_ptrs = Utils.get_values_from_cc_arg(
            arg_dst,
            state,
            rda.project.arch,
        )

        printed_str = Utils.get_strings_from_pointers(
            dst_ptrs, state, state.codeloc
        ).one_value()
        self.assertTrue(state.is_top(printed_str))
        self.assertTrue(printed_str.size() == 8 * self.TESTED_HANDLER.MAX_READ_SIZE)
