from handler_tester import HandlerTester

from angr.knowledge_plugins.key_definitions.constants import OP_AFTER
from angr.knowledge_plugins.key_definitions.atoms import Register
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from argument_resolver.handlers import handler_factory, StdlibHandlers, StringHandlers
from argument_resolver.utils.utils import Utils


class TestStdlibHandlers(HandlerTester):
    TESTED_HANDLER = handler_factory([StdlibHandlers, StringHandlers])

    def test_handle_malloc(self):
        program = """
            #include <stdlib.h>
            void main() {
                char *buf = (char *) malloc(0x40);
                char *buf2 = (char *) malloc(0x40);
            }
            """
        Utils.ALL_CALLSITES = []
        project = self.project_and_cfg_analysis_from(program)

        strcpy = project.kb.functions.function(name="malloc")
        subject = self.subject_from_function(project, strcpy)
        handler = self.TESTED_HANDLER(project, strcpy, [Register(*project.arch.registers["rdi"])])
        handler.assumed_execution = False

        rda = self.RDA(
            subject=subject,
            function_handler=handler,
            dep_graph=DepGraph(),
            observation_points=set()
        )

        malloc1, malloc2 = [x for x in handler.analyzed_list if x.function.name == 'malloc']

        self.assertEqual(Utils.get_heap_offset(malloc1.ret_val.one_value()), 0x0)
        self.assertEqual(Utils.get_heap_offset(malloc2.ret_val.one_value()), 0x40)

    def test_handle_calloc(self):
        nmemb = 0x4
        size = 0x20
        program = f"""
            #include <stdlib.h>
            void main() {{
                char *buf = (char *) calloc({nmemb}, {size});
                char *buf2 = (char *) calloc({nmemb}, {size});
            }}
            """
        project = self.project_and_cfg_analysis_from(program)


        calloc = project.kb.functions.function(name="calloc")
        observation_points = set(Utils.get_all_callsites(project))
        subject = self.subject_from_function(project, calloc)
        handler = self.TESTED_HANDLER(project, calloc, [Register(*project.arch.registers["rdi"])])
        handler.assumed_execution = False

        rda = self.RDA(
            subject=subject,
            observation_points=observation_points,
            function_handler=handler,
            dep_graph=DepGraph(),
        )

        calling_convention = project.analyses.CallingConvention(calloc).cc

        return_values = Utils.get_values_from_cc_arg(
            calling_convention.RETURN_VAL,
            handler.analyzed_list[-1].state,
            rda.project.arch,
        )

        pointer = return_values.one_value()._model_concrete.value
        state = handler.analyzed_list[-1].state
        zeroed_memory = state.heap.load(
            pointer, nmemb * size, endness=state.arch.memory_endness
        )

        self.assertEqual(pointer, nmemb * size)
        self.assertEqual(zeroed_memory.one_value().size(), nmemb * size * 8)
        self.assertEqual(zeroed_memory.one_value()._model_concrete.value, 0x0)

    def test_handle_env(self):
        env_var = "greeting"
        env_val = "Hello World!"
        program = f"""
            #include <stdlib.h>
            void main() {{
                setenv("{env_var}", "{env_val}", 0);
                getenv("{env_var}");
            }}
            """
        project = self.project_and_cfg_analysis_from(program)


        getenv = project.kb.functions["getenv"]

        subject = self.subject_from_function(project, getenv)
        observation_points = set(Utils.get_all_callsites(project))
        handler = self.TESTED_HANDLER(project, getenv, [Register(*project.arch.registers["rdi"])])
        rda = self.RDA(
            subject=subject,
            observation_points=observation_points,
            function_handler=handler,
            dep_graph=DepGraph(),
        )

        calling_convention = project.analyses.CallingConvention(getenv).cc

        state = handler.analyzed_list[-1].state
        return_values = Utils.get_values_from_cc_arg(
            calling_convention.RETURN_VAL,
            state,
            rda.project.arch,
        )

        env_string = state.heap.load(state.get_heap_offset(return_values.one_value()), len(env_val))

        self.assertEqual(
            Utils.bytes_from_int(env_string.one_value()).decode("utf-8"), env_val
        )
