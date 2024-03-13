from handler_tester import HandlerTester

from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.knowledge_plugins.key_definitions.atoms import Register
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER
from angr.knowledge_plugins.key_definitions.live_definitions import DerefSize
from argument_resolver.handlers import handler_factory, StringHandlers
from argument_resolver.utils.utils import Utils


class TestStringHandlers(HandlerTester):
    TESTED_HANDLER = handler_factory([StringHandlers])

    def test_handle_strlen(self):
        string = "Hello World!"
        program = f"""
            #include <string.h>
            void main() {{
                int i = strlen("{string}");
            }}
            """
        project = self.project_and_cfg_analysis_from(program)

        strlen = project.kb.functions.function(name="strlen")
        observation_points = set(Utils.get_all_callsites(project))
        subject = self.subject_from_function(project, strlen)
        handler = self.TESTED_HANDLER(project, strlen, [Register(*project.arch.registers["rdi"])])

        rda = self.RDA(
            subject=subject,
            observation_points=observation_points,
            function_handler=handler,
            dep_graph=DepGraph(),
        )

        calling_convention = project.analyses.CallingConvention(strlen).cc

        state = handler.analyzed_list[-1].state
        return_values = Utils.get_values_from_cc_arg(
            calling_convention.RETURN_VAL,
            state,
            rda.project.arch,
        )
        self.assertEqual(return_values.one_value()._model_concrete.value, len(string))

    def test_handle_strlen_unknown_size(self):
        program = f"""
            #include <string.h>
            void main(int argc, char **argv) {{
                int i = strlen(argv[1]);
            }}
            """
        project = self.project_and_cfg_analysis_from(program)


        strlen = project.kb.functions.function(name="strlen")
        observation_points = set(Utils.get_all_callsites(project))
        subject = self.subject_from_function(project, strlen)
        handler = self.TESTED_HANDLER(project, strlen, [Register(*project.arch.registers["rdi"])])

        rda = self.RDA(
            subject=subject,
            observation_points=observation_points,
            function_handler=handler,
            dep_graph=DepGraph(),
        )

        calling_convention = project.analyses.CallingConvention(strlen).cc

        state = handler.analyzed_list[-1].state

        return_values = Utils.get_values_from_cc_arg(
            calling_convention.RETURN_VAL,
            state,
            rda.project.arch,
        )
        self.assertTrue(state.is_top(return_values.one_value()))

    def test_handle_strcat(self):
        string1 = "Hello"
        string2 = " World!"
        program = f"""
            #include <string.h>
            void main() {{
                char buf1[0x40] = {{"{string1}"}};
                char buf2[0x40] = {{"{string2}"}};
                strcat(buf1, buf2);
            }}
        """
        project = self.project_and_cfg_analysis_from(program)


        strcat = project.kb.functions.function(name="strcat")
        subject = self.subject_from_function(project, strcat)
        observation_points = set(Utils.get_all_callsites(project))
        handler = self.TESTED_HANDLER(project, strcat, [Register(*project.arch.registers["rdi"])])

        rda = self.RDA(
            subject=subject,
            observation_points=observation_points,
            function_handler=handler,
            dep_graph=DepGraph(),
        )

        stored_func = handler.analyzed_list[-1]

        found_str = Utils.get_strings_from_pointers(stored_func.ret_val, stored_func.state, None)

        self.assertEqual(
            Utils.bytes_from_int(found_str.one_value()).decode("utf-8").replace("\x00", ""),
            string1 + string2,
        )

    def test_handle_strcat_unknown_value(self):
        string = "Hello"
        program = f"""
            #include <string.h>
            void main(int argc, char **argv) {{
                char buf[40] = {{"{string}"}};
                strcat(buf, argv[1]);
            }}
        """
        project = self.project_and_cfg_analysis_from(program)


        strcat = project.kb.functions.function(name="strcat")
        observation_points = set(Utils.get_all_callsites(project))
        subject = self.subject_from_function(project, strcat)
        handler = self.TESTED_HANDLER(project, strcat, [Register(*project.arch.registers["rdi"])])

        rda = self.RDA(
            subject=subject,
            observation_points=observation_points,
            function_handler=handler,
            dep_graph=DepGraph(),
        )

        stored_func = handler.analyzed_list[-1]

        atom = stored_func.state.deref(stored_func.ret_val.one_value(), DerefSize.NULL_TERMINATE)
        concat_str = stored_func.state.get_one_value(atom)

        self.assertEqual(Utils.bytes_from_int(concat_str[:(1 + project.arch.bytes) * 8]).decode("utf-8"), string)
        self.assertTrue(stored_func.state.is_top(concat_str[((1 + project.arch.bytes)*8) - 1:]))

    def test_handle_strcpy(self):
        program = """
            #include <string.h>
            void main() {
                char s[12];
                strcpy(s, "Hello World!");
            }
        """
        project = self.project_and_cfg_analysis_from(program)


        strcpy = project.kb.functions.function(name="strcpy")
        observation_points = set(Utils.get_all_callsites(project))
        subject = self.subject_from_function(project, strcpy)
        handler = self.TESTED_HANDLER(project, strcpy, [Register(*project.arch.registers["rdi"])])

        rda = self.RDA(
            subject=subject,
            observation_points=observation_points,
            function_handler=handler,
            dep_graph=DepGraph(),
        )

        calling_convention = project.analyses.CallingConvention(strcpy).cc

        state = handler.analyzed_list[-1].state

        return_values = Utils.get_values_from_cc_arg(
            calling_convention.RETURN_VAL, state, rda.project.arch
        )
        resulting_string_bytes = Utils.get_strings_from_pointers(return_values, state, None)
        data = Utils.bytes_from_int(resulting_string_bytes.one_value())
        self.assertEqual(data.decode("utf-8"), "Hello World!")

    def test_handle_strcpy_unknown_value(self):
        program = """
            #include <string.h>
            void main(int argc, char **argv) {
                char s[12];
                strcpy(s, argv[1]);
            }
        """
        project = self.project_and_cfg_analysis_from(program)


        strcpy = project.kb.functions.function(name="strcpy")
        observation_points = set(Utils.get_all_callsites(project))
        subject = self.subject_from_function(project, strcpy)
        handler = self.TESTED_HANDLER(project, strcpy, [Register(*project.arch.registers["rdi"])])

        rda = self.RDA(
            subject=subject,
            observation_points=observation_points,
            function_handler=handler,
            dep_graph=DepGraph(),
        )

        calling_convention = project.analyses.CallingConvention(strcpy).cc

        state = handler.analyzed_list[-1].state

        return_values = Utils.get_values_from_cc_arg(
            calling_convention.RETURN_VAL, state, rda.project.arch
        )

        resulting_string_bytes = Utils.get_strings_from_pointers(return_values, state, None)

        self.assertTrue(state.is_top(resulting_string_bytes.one_value()))

    def test_handle_strncpy(self):
        program = """
            #include <string.h>
            void main() {
                char s[5];
                strncpy(s, "Hello World!", 5);
            }
        """
        project = self.project_and_cfg_analysis_from(program)


        strncpy = project.kb.functions.function(name="strncpy")
        observation_points = set(Utils.get_all_callsites(project))
        subject = self.subject_from_function(project, strncpy)
        handler = self.TESTED_HANDLER(project, strncpy, [Register(*project.arch.registers["rdi"])])

        rda = self.RDA(
            subject=subject,
            observation_points=observation_points,
            function_handler=handler,
            dep_graph=DepGraph(),
        )

        calling_convention = project.analyses.CallingConvention(strncpy).cc

        state = handler.analyzed_list[-1].state

        return_values = Utils.get_values_from_cc_arg(
            calling_convention.RETURN_VAL, state, rda.project.arch
        )

        resulting_string = Utils.get_strings_from_pointers(return_values, state, None)

        # We handle strncpy as strcpy
        self.assertEqual(Utils.bytes_from_int(resulting_string.one_value()).decode("utf-8"), "Hello World!")

    def test_handle_strncpy_unknown_value(self):
        program = """
            #include <string.h>
            void main(int argc, char **argv) {
                char s[5];
                strncpy(s, argv[1], 5);
            }
        """
        project = self.project_and_cfg_analysis_from(program)


        strncpy = project.kb.functions.function(name="strncpy")
        observation_points = set(Utils.get_all_callsites(project))
        subject = self.subject_from_function(project, strncpy)
        handler = self.TESTED_HANDLER(project, strncpy, [Register(*project.arch.registers["rdi"])])

        rda = self.RDA(
            subject=subject,
            observation_points=observation_points,
            function_handler=handler,
            dep_graph=DepGraph(),
        )

        calling_convention = project.analyses.CallingConvention(strncpy).cc

        state = handler.analyzed_list[-1].state
        return_values = Utils.get_values_from_cc_arg(
            calling_convention.RETURN_VAL, state, rda.project.arch
        )

        resulting_string = Utils.get_strings_from_pointers(return_values, state, None)

        self.assertTrue(state.is_top(resulting_string.one_value()))

    def test_handle_atoi(self):
        string = "42"
        program = f"""
            #include <string.h>
            void main() {{
                char *s = "{string}";
                int i = atoi(s);
            }}
        """
        project = self.project_and_cfg_analysis_from(program)


        atoi = project.kb.functions.function(name="atoi")
        observation_points = set(Utils.get_all_callsites(project))
        subject = self.subject_from_function(project, atoi)
        handler = self.TESTED_HANDLER(project, atoi, [Register(*project.arch.registers["rdi"])])

        rda = self.RDA(
            subject=subject,
            observation_points=observation_points,
            function_handler=handler,
            dep_graph=DepGraph(),
        )
        stored_func = handler.analyzed_list[-1]

        self.assertEqual(stored_func.ret_val.one_value()._model_concrete.value, int(string))

    def test_handle_atoi_unknown_value(self):
        program = """
            #include <string.h>
            void main(int argc, char **argv) {
                int i = atoi(argv[1]);
            }
        """
        project = self.project_and_cfg_analysis_from(program)


        atoi = project.kb.functions.function(name="atoi")
        observation_points = set(Utils.get_all_callsites(project))
        subject = self.subject_from_function(project, atoi)
        handler = self.TESTED_HANDLER(project, atoi, [Register(*project.arch.registers["rdi"])])

        rda = self.RDA(
            subject=subject,
            observation_points=observation_points,
            function_handler=handler,
            dep_graph=DepGraph(),
        )

        stored_func = handler.analyzed_list[-1]
        self.assertTrue(stored_func.state.is_top(stored_func.ret_val.one_value()))

    def test_handle_memcpy(self):
        string = "Hello World!"
        program = f"""
            #include <string.h>
            void main() {{
                char s[12];
                memcpy(s, "{string}", 12);
            }}
        """
        project = self.project_and_cfg_analysis_from(program)


        memcpy = project.kb.functions.function(name="memcpy")
        observation_points = set(Utils.get_all_callsites(project))
        subject = self.subject_from_function(project, memcpy)
        handler = self.TESTED_HANDLER(project, memcpy, [Register(*project.arch.registers["rdi"])])

        rda = self.RDA(
            subject=subject,
            observation_points=observation_points,
            function_handler=handler,
            dep_graph=DepGraph(),
        )

        stored_func = handler.analyzed_list[-1]
        memory_value = Utils.get_strings_from_pointers(stored_func.ret_val, stored_func.state, None)

        self.assertEqual(
            Utils.bytes_from_int(memory_value.one_value()).decode("utf-8"),
            string,
        )

    def test_handle_memcpy_unknown_value(self):
        program = """
            #include <string.h>
            void main(int argc, char **argv) {
                char s[12];
                memcpy(s, argv[1], 12);
            }
        """
        project = self.project_and_cfg_analysis_from(program)


        memcpy = project.kb.functions.function(name="memcpy")
        observation_point = ("node", memcpy.addr, OP_AFTER)
        subject = self.subject_from_function(project, memcpy)
        handler = self.TESTED_HANDLER(project, memcpy, [Register(*project.arch.registers["rdi"])])

        rda = self.RDA(
            subject=subject,
            observation_points={observation_point},
            function_handler=handler,
            dep_graph=DepGraph(),
        )

        stored_func = handler.analyzed_list[-1]
        memory_value = Utils.get_strings_from_pointers(stored_func.ret_val, stored_func.state, None)

        self.assertTrue(stored_func.state.is_top(memory_value.one_value()))

    def test_handle_memset(self):
        byte = 0
        size = 10
        program = f"""
            #include <string.h>
            void main() {{
                char s[10];
                memset(s, {byte}, {size});
            }}
        """
        project = self.project_and_cfg_analysis_from(program)


        memset = project.kb.functions.function(name="memset")
        observation_points = set(Utils.get_all_callsites(project))
        subject = self.subject_from_function(project, memset)
        handler = self.TESTED_HANDLER(project, memset, [Register(*project.arch.registers["rdi"])])

        rda = self.RDA(
            subject=subject,
            observation_points=observation_points,
            function_handler=handler,
            dep_graph=DepGraph(),
        )

        stored_func = handler.analyzed_list[-1]
        memory_value = stored_func.state.stack.load(
            stored_func.state.get_stack_address(stored_func.ret_val.one_value()), size
        )

        self.assertEqual(
            Utils.bytes_from_int(memory_value.one_value()).decode("utf-8"),
            chr(byte) * size,
        )

    def test_handle_strdup(self):
        test_string = "Hello World!"
        program = f"""
            #include <string.h>
            void main() {{
                char *s = strdup("{test_string}");
            }}
        """
        project = self.project_and_cfg_analysis_from(program)


        strdup = project.kb.functions.function(name="strdup")
        observation_points = set(Utils.get_all_callsites(project))
        subject = self.subject_from_function(project, strdup)
        handler = self.TESTED_HANDLER(project, strdup, [Register(*project.arch.registers["rdi"])])

        rda = self.RDA(
            subject=subject,
            observation_points=observation_points,
            function_handler=handler,
            dep_graph=DepGraph(),
        )

        calling_convention = project.analyses.CallingConvention(strdup).cc

        state = handler.analyzed_list[-1].state

        return_values = Utils.get_values_from_cc_arg(
            calling_convention.RETURN_VAL, state, rda.project.arch
        )

        duplicated_string = Utils.get_strings_from_pointers(return_values, state, None)

        self.assertEqual(
            Utils.bytes_from_int(duplicated_string.one_value()).decode("utf-8"),
            test_string,
        )
