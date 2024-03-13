import os
import subprocess
import tempfile

from unittest import TestCase
from typing import Tuple

from angr.project import Project
from angr.analyses.analysis import AnalysisFactory

from argument_resolver.utils.rda import CustomRDA
from argument_resolver.utils.call_trace_visitor import CallTraceSubject
from argument_resolver.utils.call_trace import traces_to_sink


class HandlerTester(TestCase):
    """
    Helper to test handlers.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.folder = ""
        self.source_path = ""
        self.binary_path = ""
        self.RDA = None

    def subject_from_function(self, project, function, depth=1):
        traces = traces_to_sink(function, project.kb.functions.callgraph, depth, [])
        assert len(traces) == 1

        trace = traces.pop()
        function_address = trace.current_function_address()
        init_function = project.kb.functions[function_address]
        return CallTraceSubject(trace, init_function)


    def project_and_cfg_analysis_from(self, program: str) -> Project:
        """
        Build an `angr.Project` for a program corresponding to a given C source;
        Then run the `CFGFast` analysis on it.
        """
        binary = self._compile(program)
        project = Project(binary, auto_load_libs=False)
        cfg = project.analyses.CFGFast(normalize=True, data_references=True)
        project.analyses.CompleteCallingConventions(recover_variables=True, cfg=cfg)
        self.RDA = AnalysisFactory(project, CustomRDA)

        return project

    def _compile(self, program: str) -> str:
        """
        Compile a binary given a source.

        :param program: The program source code in C.
        :return: The absolute path of the generated binary on the filesystem.
        """
        self.folder = tempfile.TemporaryDirectory()

        self.source_path = os.path.join(self.folder.name, "program.c")
        with open(self.source_path, "w", encoding="ascii") as source_file:
            source_file.write(program)

        self.binary_path = os.path.join(self.folder.name, "program")

        subprocess.call(
            [
                "gcc",
                "-O0",
                "-w",
                "-fno-builtin",
                "-fno-stack-protector",
                self.source_path,
                "-o",
                self.binary_path,
            ]
        )

        return self.binary_path
