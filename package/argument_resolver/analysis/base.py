import argparse
import json
import logging
import os
import signal
import subprocess
import shutil
import sys
import time
import ipdb
import inspect
import concurrent.futures

from multiprocessing import cpu_count
from pathlib import Path
from collections import Counter
from typing import Any, Dict, Generator, List, Optional, Set, Tuple, NamedTuple

import psutil

from rich.progress import (
    Progress,
    TextColumn,
    BarColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

import angr
from angr.analyses.analysis import AnalysisFactory
from angr.analyses.reaching_definitions.call_trace import CallTrace
from angr.code_location import CodeLocation
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.analyses.reaching_definitions.reaching_definitions import (
    ReachingDefinitionsAnalysis,
)
from angr.knowledge_plugins.functions.function import Function
from angr.knowledge_plugins.key_definitions.atoms import Atom
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER, OP_BEFORE
from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions

from argument_resolver.external_function.function_declarations import CUSTOM_DECLS
from argument_resolver.external_function.sink import Sink, VULN_TYPES
from argument_resolver.formatters.closure_formatter import ClosureFormatter
from argument_resolver.formatters.log_formatter import make_logger
from argument_resolver.handlers import (
    NVRAMHandlers,
    NetworkHandlers,
    StdioHandlers,
    StdlibHandlers,
    StringHandlers,
    UnistdHandlers,
    URLParamHandlers,
    handler_factory,
)
from argument_resolver.handlers.base import HandlerBase
from argument_resolver.utils.call_trace import traces_to_sink
from argument_resolver.utils.call_trace_visitor import CallTraceSubject
from argument_resolver.utils.calling_convention import (
    CallingConventionResolver,
    LIBRARY_DECLS,
)
from argument_resolver.utils.rda import CustomRDA
from argument_resolver.utils.stored_function import StoredFunction
from argument_resolver.utils.utils import Utils
from argument_resolver.formatters.log_formatter import CustomTextColumn


class ScriptBase:
    def __init__(
        self,
        bin_path: str,
        sink: str = None,
        source_function="main",
        min_depth=1,
        max_depth=1,
        arg_pos=0,
        ld_paths=None,
        excluded_functions=None,
        result_path: str = None,
        disable_progress_bar=True,
        sink_category=None,
        env_dict: str = None,
        workers: int = 1,
        rda_timeout: int = 0,
        full_exec: bool = False,
        forward_trace: bool = False,
        log_level=logging.INFO,
        enable_breakpoint=False,
        keyword_dict: str = None,
    ):

        self.bin_path = bin_path
        self.min_depth = min_depth if not forward_trace else max_depth
        self.max_depth = max_depth
        self.excluded_functions = {}
        self.source = source_function
        self.assumed_execution = not full_exec
        self.forward_trace = forward_trace
        self.trace_dict = {}
        self.sinks_found = {}
        self.rda_task = None
        self.trace_task = None
        self.enable_breakpoint = enable_breakpoint
        self.category = sink_category
        if keyword_dict is None:
            self.keyword_dict = dict()
        else:
            with open(keyword_dict, "r") as f:
                self.keyword_dict = json.load(f)

        self.cfg_time = 0
        self.vra_time = 0
        self.analysis_start_time = 0
        self.analysis_time = 0
        self.rda_timeout = rda_timeout
        self.vra_start_time = 0
        self.time_data = {}
        self.sink_time = 0

        self.Handler = handler_factory(
            [
                StdioHandlers,
                StdlibHandlers,
                StringHandlers,
                UnistdHandlers,
                NVRAMHandlers,
                NetworkHandlers,
                URLParamHandlers,
            ]
        )

        self.result_path = Path(result_path) if result_path is not None else None
        self.alarm_triggered = False

        if self.result_path is not None:
            self.log_path = self.result_path / f"{self.category}_mango.out"
        self.log = make_logger(log_level=log_level, should_debug=self.result_path)
        logging.getLogger("angr").setLevel(logging.CRITICAL)

        self.progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            CustomTextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
        )

        self.set_breakpoint_handler()
        self.project = self.init_analysis(
            workers=workers,
            show_progress_bar=not disable_progress_bar,
            ld_paths=ld_paths,
        )
        self.env_dict = self.load_env_dict(env_dict)
        if self.keyword_dict:
            self.rename_form_param_parser()
        self.sinks = self.load_sinks(
            custom_sink=sink, arg_pos=arg_pos, category=sink_category
        )
        self.excluded_functions = self.load_excluded_functions(
            excluded_functions=excluded_functions
        )

        self._calling_convention_resolver = CallingConventionResolver(
            self.project,
            self.project.arch,
            self.project.kb.functions,
        )

        self.overwrite_func_prototypes()

        self.result_formatter = ClosureFormatter(
            self.project, self._calling_convention_resolver
        )

        self.RDA = AnalysisFactory(self.project, CustomRDA)

    def set_breakpoint_handler(self):
        sys.breakpointhook = self.breakpoint_handler

    def breakpoint_handler(self, *args, **kwargs):
        if self.progress is not None:
            self.progress.stop()
        frame = inspect.currentframe().f_back
        ipdb.set_trace(frame)

    def init_analysis(self, workers: int, show_progress_bar: bool, ld_paths: list):
        if ld_paths is None or ld_paths == "None":
            project = angr.Project(self.bin_path, auto_load_libs=False)
        else:
            project = angr.Project(
                self.bin_path,
                auto_load_libs=True,
                load_options={"ld_path": ld_paths, "skip_libs": ["libc.so.0"]},
            )

        start = time.time()
        project.analyses.CFGFast(
            normalize=True, data_references=True, show_progressbar=show_progress_bar
        )
        self.cfg_time = time.time() - start

        # Run CC analysis
        start = time.time()
        # Allow for 20 min of VRA
        self.vra_start_time = start
        vra_task = self.progress.add_task("Running VRA", total=None)
        self.progress.start_task(vra_task)
        self.progress.start()

        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(project.analyses.CompleteCallingConventions,
                                    recover_variables=True,
                                    analyze_callsites=True,
                                    workers=workers
                                    )
            try:
                future.result(timeout=20*60)
            except concurrent.futures.TimeoutError:
                future.cancel()
                # Failed to finish vra in time
                self.log.critical("VRA TIMED OUT")
                exit(-1)
        self.vra_time = time.time() - start
        self.vra_start_time = 0
        self.progress.update(vra_task, completed=1, total=1, visible=False)
        self.progress.remove_task(vra_task)
        Utils.arch = project.arch

        return project

    def rename_form_param_parser(self):
        if not self.keyword_dict:
            return

        cfg = self.project.kb.cfgs.get_most_accurate()
        strings = [x for x in cfg.memory_data.items() if x[1].sort == "string"]
        strings = [
            x
            for x in strings
            if x[1].content.decode("latin-1") in self.keyword_dict
            or x[1].content.decode("latin-1").replace("=", "") in self.keyword_dict
        ]
        all_addrs = Counter()
        for addr, string in strings:
            for xref in self.project.kb.xrefs.get_xrefs_by_dst(addr):
                node = cfg.get_any_node(xref.block_addr)
                if node is None:
                    continue

                call_addrs = {
                    x[1].function_address
                    for x in cfg.graph.out_edges(node, data=True)
                    if x[-1]["jumpkind"] == "Ijk_Call"
                }
                all_addrs.update(call_addrs)
        all_funcs = [self.project.kb.functions[x] for x in all_addrs]
        all_funcs = [
            x
            for x in all_funcs
            if x.name not in LIBRARY_DECLS and "nvram" not in x.name.lower()
        ]
        blacklist = ["GetIniFileValue"]
        for name in blacklist:
            if name in all_funcs:
                all_funcs.remove(name)

        if len(all_funcs) == 0:
            return
        param_func = max(all_funcs, key=lambda x: all_addrs[x.addr])
        self.project.kb.functions[param_func.name].name = "custom_param_parser"

    def overwrite_func_prototypes(self):
        for func_name, prototype in CUSTOM_DECLS.items():
            if func_name in self.project.kb.functions:
                self.project.kb.functions[func_name].prototype = prototype

    def load_excluded_functions(
        self, excluded_functions: List[str] = None
    ) -> Dict[Function, Set[Tuple]]:

        default_excluded_functions = self.find_default_excluded_functions()
        excluded_dict = {}
        valid_sinks = []
        for f_sink in self.sinks:
            if f_sink.name not in self.project.kb.functions:
                continue
            valid_sinks.append(f_sink.name)
            sink_func = self.project.kb.functions[f_sink.name]
            excluded_dict[sink_func] = default_excluded_functions

            if excluded_functions is None:
                continue

            for func in excluded_functions:
                if func in self.project.kb.functions:
                    excluded_dict[sink_func].add(
                        (self.project.kb.functions[func], None)
                    )
        if len(valid_sinks) > 0:
            self.log.critical("TARGETING SINKS: %s", ", ".join(valid_sinks))
        else:
            self.log.critical("NO SINKS FOUND")
        return excluded_dict

    @staticmethod
    def load_sinks(custom_sink=None, arg_pos=None, category=None) -> List[Sink]:
        sinks = []
        if custom_sink and arg_pos:
            sinks = [Sink(custom_sink, [arg_pos + 1])]
        else:
            category = category.lower()
            if category in VULN_TYPES:
                sinks = VULN_TYPES[category]
            if len(sinks) == 0:
                sinks = VULN_TYPES["cmdi"]
        return sinks

    @staticmethod
    def load_env_dict(env_dict_path: str) -> Optional[Dict]:
        if env_dict_path is not None:
            env_dict = json.loads(Path(env_dict_path).read_text())
        else:
            env_dict = {}

        return env_dict

    def update_rda_task(self, parent_name, parent_addr, child_name, child_addr):
        self.progress.update(
            self.rda_task,
            description=f"Analyzing {parent_name}@{parent_addr}->{child_name}@{child_addr}",
            advance=1,
        )

    def update_trace_task(self, parent_name, parent_addr, child_name, child_addr):
        self.progress.update(
            self.trace_task,
            description=f"Tainting {parent_name}@{parent_addr}->{child_name}@{child_addr}",
            advance=1,
        )

    def analyze(self):
        self.analysis_start_time = time.time()

        try:
            for sink, sink_function in self.get_sink_callsites(self.sinks):

                sink_start = time.time()
                sink_count = 0
                atoms = Utils.get_atoms_from_function(sink_function, self.project.arch)
                atoms = [
                    atom
                    for idx, atom in enumerate(atoms)
                    if idx + 1 in sink.vulnerable_parameters
                ]

                cfg = self.project.kb.cfgs.get_most_accurate()
                self.sinks_found[sink_function.name] = len(
                    {
                        x.addr
                        for x in cfg.get_predecessors(
                            cfg.get_any_node(sink_function.addr)
                        )
                    }
                )
                traces = self.gen_traces_to_sink(
                    sink_function, self.max_depth + 1, atoms
                )
                analysis_task = self.progress.add_task(
                    f"Tracing path to sink {sink_function.name}", total=None
                )
                taint_start = time.time()
                total_traces = 0
                for trace, white_list, trace_idx, total_traces in traces:
                    taint_time = time.time() - taint_start

                    sink_count += 1
                    observation_points = self.get_observation_points_from_trace(trace)

                    rda_start = time.time()
                    rda, handler = self.run_analysis_on_trace(
                        trace, white_list, sink_function, atoms, observation_points
                    )
                    rda_time = time.time() - rda_start
                    self.sink_time = time.time() - sink_start
                    callsite_tup = tuple(
                        [x.caller_func_addr for x in trace.callsites]
                        + [sink_function.addr]
                    )
                    self.time_data[callsite_tup] = {
                        "taint_time": taint_time,
                        "rda_time": rda_time,
                    }
                    process_task = self.progress.add_task(
                        "Analyzing Results from RDA", total=None
                    )
                    self.process_rda(rda, handler)
                    self.progress.update(process_task, visible=False)
                    taint_start = time.time()
                    self.progress.update(
                        analysis_task, total=total_traces, completed=trace_idx
                    )
                    self.log.info(
                        f"Analyzed %s/%s for sink %s",
                        trace_idx,
                        total_traces,
                        sink_function.name,
                    )

                self.progress.update(
                    analysis_task, total=total_traces, completed=total_traces
                )
            self.analysis_time = time.time() - self.analysis_start_time
            self.progress.stop()
            self.save_results()
            self.log.info("Finished Running Analysis")
            temp_path = Path("/tmp/mango.out")
            if temp_path.exists() and self.result_path:
                self.result_path.mkdir(parents=True, exist_ok=True)
                shutil.move(temp_path, self.log_path)
        except Exception:
            self.progress.stop()
            self.log.exception("OH NO MY MANGOES!!!")
            exc_type, exc_value, exc_traceback = sys.exc_info()
            if self.enable_breakpoint:
                ipdb.post_mortem(exc_traceback)
            exit(-1)

    def save_results(self):
        """
        Save results of analysis
        :return:
        """
        pass

    def find_default_excluded_functions(self) -> Set[Tuple[int, Any]]:
        # If `main` is present, don't let calltraces go beyond it: it is as good as if the entrypoint was reached.
        if self.source is None:
            return set()

        functions_before_source = set()
        main_func = self.project.kb.functions.function(name="main")
        if main_func:
            functions_before_source = {
                (x, None)
                for x in self.project.kb.callgraph.predecessors(main_func.addr)
            }

        # Due to the nature of its disassembly and CFG reconstitution,
        # `angr` marks certain alignment blocks from the binary as functions
        # and keeps them in the callgraph (see https://github.com/angr/angr/issues/2366 for an example);
        # We don't want that to be part of our calltraces.
        alignment_functions = {
            (f.addr, None) for f in self.project.kb.functions.values() if f.alignment
        }

        return functions_before_source | alignment_functions

    def get_sink_callsites(self, sinks: List[Sink]) -> List[Tuple[Sink, Function]]:
        """
        :return:
            A list of tuples, for each sink present in the binary, containing:
            the representation of the <Sink> itself, the <Function> representation.
        """

        final_sinks = []
        for sink in sinks:
            function = self.project.kb.functions.function(name=sink.name)
            if function is None:
                continue

            if function.calling_convention is None:
                function.calling_convention = self._calling_convention_resolver.get_cc(
                    function.name
                )
                if hasattr(function.calling_convention, "sim_func"):
                    function.prototype = function.calling_convention.sim_func

            if function.prototype is None:
                function.prototype = self._calling_convention_resolver.get_prototype(
                    function.name
                )

            final_sinks.append((sink, function))

        return final_sinks

    def gen_traces_to_sink(
        self, sink: Function, max_depth: int, atoms: List[Atom]
    ) -> Generator[Tuple[CallTrace, List[StoredFunction]], None, None]:
        """
        :param sink: Function to build trace to
        :param atoms: Target atoms in sink
        :param max_depth: The maximum length of the path between the sink and the uncovered start point.

        :return:
            A tuple containing:
            - A boolean telling if every trace is as high as possible (from the sink to the entrypoint of the binary);
            - A generator to run a <ReachingDefinitionsAnalysis> for every start found under the given max_depth.
        """

        traces = []
        for depth in range(1, max_depth):
            sub_traces: Set[CallTrace] = traces_to_sink(
                sink,
                self.project.kb.functions.callgraph,
                depth,
                self.excluded_functions[sink],
            )
            for s_t in sub_traces:
                callsites = {
                    (y.caller_func_addr, y.callee_func_addr) for y in s_t.callsites
                }
                for trace in traces.copy():
                    if all(
                        (x.caller_func_addr, x.callee_func_addr) in callsites
                        for x in trace.callsites
                    ):
                        traces.remove(trace)
                traces.append(s_t)

        if not self.forward_trace:
            analyzed_traces = set()
            total_traces = len(traces)

            for idx, trace in enumerate(
                sorted(traces.copy(), key=lambda x: len(x.callsites))
            ):
                new_trace, white_list = self.check_trace_rda(trace, sink, atoms)

                traces.remove(trace)
                if not new_trace.callsites:
                    continue
                # Don't bother analyzing anything that doesn't have a known_set location
                # if not any(x.code_loc.ins_addr in valid_set_locations for x in white_list):
                #    continue
                callsites = [
                    {x.caller_func_addr for x in trace.callsites} for trace in traces
                ]
                if (
                    new_trace.callsites
                    and {x.caller_func_addr for x in new_trace.callsites}
                    not in callsites
                    and not any(
                        self._is_trace_subset(new_trace, x) in {1, 0}
                        for x in analyzed_traces
                    )
                ):
                    analyzed_traces.add(new_trace)

                    yield new_trace, white_list, idx, total_traces

        else:
            for t_1 in traces.copy():
                for t_2 in traces.copy():
                    if self._is_trace_subset(t_1, t_2) == 1:
                        traces.remove(t_2)
            for idx, trace in enumerate(sorted(traces, key=lambda x: len(x.callsites))):
                yield trace, [], idx, len(traces)

    @staticmethod
    def _is_trace_subset(trace_1, trace_2):
        callsites_1 = {
            (x.caller_func_addr, x.callee_func_addr) for x in trace_1.callsites
        }
        callsites_2 = {
            (x.caller_func_addr, x.callee_func_addr) for x in trace_2.callsites
        }

        if callsites_1 < callsites_2:
            return 1

        if callsites_1 > callsites_2:
            return -1

        if callsites_1 == callsites_2:
            return 0

        return None

    def get_observation_points_from_trace(
        self, trace: CallTrace
    ) -> Set[Tuple[str, int, int]]:
        def _call_statement_in_node(node) -> Optional[int]:
            """
            Assuming the node is the predecessor of a function start.
            Returns the statement address of the `call` instruction.
            """
            if node is None or node.block is None:
                return None

            if (
                self.project.arch.branch_delay_slot
                and node.block.disassembly.insns[-1].mnemonic == "nop"
            ):
                return node.block.instruction_addrs[-2]
            return node.block.instruction_addrs[-1]

        observation_points = set()
        cfg = self.project.kb.cfgs.get_most_accurate()
        # Get final call to target function
        for pred in cfg.get_any_node(trace.callsites[0].callee_func_addr).predecessors:
            if pred.function_address != trace.callsites[0].caller_func_addr:
                continue

            callsite = _call_statement_in_node(pred)
            if callsite is None:
                continue

            observation_points.add(("insn", callsite, OP_AFTER))
            observation_points.add(("node", callsite, OP_AFTER))
            observation_points.add(("node", callsite, OP_BEFORE))

        return observation_points

    def check_trace_rda(self, trace: CallTrace, sink: Function, sink_atoms: List[Atom]):
        white_list = set()
        final_trace = CallTrace(trace.target)

        target_atoms = sink_atoms
        WListFunc = NamedTuple("WListFunc", [("code_loc", CodeLocation)])

        for call_idx, callsite in enumerate(trace.callsites):
            callsite_tuple = tuple(
                [x.caller_func_addr for x in reversed(trace.callsites[: call_idx + 1])]
                + [trace.callsites[0].callee_func_addr]
            )
            if sink in self.trace_dict and callsite_tuple in self.trace_dict[sink]:
                final_trace.callsites.append(callsite)
                data = self.trace_dict[sink][callsite_tuple]
                white_list |= set(data["white_list"])
                if data["final"]:
                    break
                else:
                    continue

            single_trace = CallTrace(callsite.callee_func_addr)
            single_trace.callsites = [callsite]
            function_address = single_trace.current_function_address()
            function = self.project.kb.functions[function_address]
            subject = CallTraceSubject(single_trace, function)
            handler = self.Handler(
                self.project,
                sink,
                target_atoms,
                env_dict=self.env_dict,
                taint_trace=True,
                progress_callback=self.update_trace_task,
            )

            self.log.info(
                "Running RDA Taint on function %s@%#x...",
                function.name,
                function_address,
            )
            self.log.debug(
                "Trace: %s",
                "".join(
                    [
                        f"{self.project.kb.functions[x.caller_func_addr].name}->"
                        for x in reversed(single_trace.callsites)
                    ]
                    + [self.project.kb.functions[single_trace.target].name]
                ),
            )

            timed_out = False
            self.trace_task = self.progress.add_task(f"Tainting ...", total=None)
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(self.RDA,
                                         subject=subject,
                                         function_handler=handler,
                                         observation_points=set(),
                                         init_context=(callsite.caller_func_addr,),
                                         start_time=time.time(),
                                         kb=self.project.kb,
                                         dep_graph=DepGraph(),
                                         max_iterations=2,
                                         )

                try:
                    future.result(timeout=self.rda_timeout if self.rda_timeout > 0 else None)
                except concurrent.futures.TimeoutError:
                    timed_out = True
                    future.cancel()
                    self.log.critical("Timed out for trace %s", single_trace.callsites)
                finally:
                    executor.shutdown(wait=False)


            self.progress.update(self.trace_task, visible=False)
            self.progress.remove_task(self.trace_task)

            if timed_out:
                break

            if sink not in self.trace_dict:
                self.trace_dict[sink] = {}

            sinks = [
                x for x in handler.white_list if x.function.addr == single_trace.target
            ]

            self.trace_dict[sink][callsite_tuple] = {
                "white_list": [
                    WListFunc(code_loc=x.code_loc) for x in handler.white_list
                ],
                "final": False,
                "valid_sinks": set(),
                "constant": set(),
                "input": None,
            }
            concrete = True

            for target_func in sinks:
                for atom in target_func.atoms:
                    # TODO: This is a lazy fix, add better support for execve
                    if atom not in target_atoms and not target_func.name.startswith(
                        "exec"
                    ):
                        continue
                    if target_func.constant_data[atom] is None:
                        continue

                    for d in target_func.constant_data[atom]:
                        if d is None:
                            concrete = False
                            break
                        elif (
                            d.concrete_value == 0x0
                            and atom in target_func.arg_vals
                            and str(d) not in str(target_func.arg_vals[atom])
                        ):
                            concrete = False
                            break
                if not concrete:
                    break

            has_only_constant_func = not handler.white_list
            has_only_constant_func |= (
                len(handler.white_list) == 1
                and handler.white_list[0].function.addr == single_trace.target
            )

            # If the sink arguments are constant
            # we can stop the trace and use the constant values as input for the rda
            if (
                concrete
                and has_only_constant_func
                and not self.__class__.__name__ == "EnvAnalysis"
            ):
                if len(final_trace.callsites) > 0:
                    sink_val_list = [
                        x
                        for x in handler.white_list
                        if x.function.addr == single_trace.target
                    ]
                    if len(sink_val_list) > 0:
                        sink_val = sink_val_list[0]
                        self.trace_dict[sink][callsite_tuple]["input"] = sink_val.state
                        self.trace_dict[sink][callsite_tuple]["final"] = True
                        final_trace.callsites.append(callsite)
                break

            next_atoms = set()
            has_arg_reference = False
            has_internal_dependencies = False
            for func in handler.white_list:
                if func.function.addr == sink.addr:
                    self.trace_dict[sink][callsite_tuple]["valid_sinks"].add(
                        func.code_loc.ins_addr
                    )

                if func.function.addr == single_trace.target:
                    if any(
                        defn not in func.definitions
                        for atom in [a for a in target_atoms if a in func.closures]
                        for defn in func.closures[atom]
                    ):
                        has_internal_dependencies = True
                if func != handler.call_trace[0]:
                    valid_defns = [
                        defn
                        for defn in func.definitions
                        if defn in handler.call_trace[0].definitions
                    ]
                    if valid_defns:
                        has_arg_reference = True
                        next_atoms |= set(d.atom for d in valid_defns)
                        continue

                    valid_closures = [
                        closure
                        for closure in func.closures.values()
                        if closure.intersection(handler.call_trace[0].definitions)
                    ]
                    if valid_closures:
                        has_arg_reference = True
                        next_atoms |= set(
                            d.atom
                            for closure in valid_closures
                            for d in closure
                            if d in handler.call_trace[0].definitions
                        )

            target_atoms = list(next_atoms)

            if (
                single_trace.target == sink.addr
                and not (has_internal_dependencies or has_arg_reference)
                and not self.__class__.__name__ == "EnvAnalysis"
            ):
                # No dependency on parent func if reached
                self.trace_dict[sink][callsite_tuple]["constant"] = True
                break

            if has_internal_dependencies or has_arg_reference:
                final_trace.callsites.append(callsite)
                white_list |= set(
                    WListFunc(code_loc=x.code_loc) for x in handler.white_list
                )

            elif self.__class__.__name__ == "EnvAnalysis":
                final_trace.callsites.append(callsite)
                white_list |= set(
                    WListFunc(code_loc=x.code_loc) for x in handler.white_list
                )
                self.trace_dict[sink][callsite_tuple]["final"] = True
                break

            if not has_arg_reference or not handler.current_parent.atoms:
                self.trace_dict[sink][callsite_tuple]["final"] = True
                break

        return final_trace, white_list

    def run_analysis_on_trace(
        self,
        trace: CallTrace,
        white_list: List[StoredFunction],
        sink: Function,
        sink_atoms: List[Atom],
        observation_points: Set[Tuple[str, int, int]],
    ):
        """
        Generator to get RDA analyses for each start point of the CFG at a given depth.
        :param traces: The set of CallTraces leading to the sink
        :param sink: The sink
        :param sink_atoms: The atoms and their respective types representing the arguments flowing into the subject (sink).
        :param observation_points: Livedef states to preserve at address.
        :param timeout: Seconds until RDA is cancelled
        """

        handler = self.Handler(
            self.project,
            sink,
            sink_atoms,
            env_dict=self.env_dict,
            assumed_execution=self.assumed_execution,
            forward_trace=self.forward_trace,
            progress_callback=self.update_rda_task,
        )
        if self.assumed_execution:
            handler.white_list = white_list

        trace_tup = tuple(
            [x.caller_func_addr for x in reversed(trace.callsites)]
            + [trace.callsites[0].callee_func_addr]
        )

        init_state = None
        if sink in self.trace_dict and trace_tup in self.trace_dict[sink]:
            init_state = self.trace_dict[sink][trace_tup]["input"]
            if init_state is not None:
                trace.callsites.pop()

        function_address = trace.current_function_address()
        function = self.project.kb.functions[function_address]
        subject = CallTraceSubject(trace, function)

        self.log.info(
            "Running RDA on function %s@%#x...", function.name, function_address
        )
        self.log.debug(
            "Trace: %s",
            "".join(
                [
                    f"{self.project.kb.functions[x.caller_func_addr].name}->"
                    for x in reversed(trace.callsites)
                ]
                + [sink.name]
            ),
        )

        all_callsites = set(Utils.get_all_callsites(self.project))
        all_callsites.update(observation_points)

        self.rda_task = self.progress.add_task(f"Analyzing ...", total=None)

        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(self.RDA,
                                    subject=subject,
                                    observation_points=all_callsites,
                                    function_handler=handler,
                                    kb=self.project.kb,
                                    dep_graph=DepGraph(),
                                    start_time=time.time(),
                                    init_state=init_state,
                                    max_iterations=2,
                                    )

            try:
                rda = future.result(timeout=self.rda_timeout if self.rda_timeout > 0 else None)
            except concurrent.futures.TimeoutError:
                rda = None
                future.cancel()
                self.log.critical( "TIMEOUT FOR subject: %s, sink: %s", subject.content.callsites, sink.name)
            finally:
                executor.shutdown(wait=False)

        self.progress.update(self.rda_task, visible=False)
        self.progress.remove_task(self.rda_task)

        handler.call_trace.clear()

        return rda, handler

    def process_rda(self, dep: CustomRDA, handler: HandlerBase):

        fully_resolved = True

        self.log.debug("Starting Post Analysis")
        resolved = self.post_analysis(dep, handler)
        fully_resolved &= resolved

        if resolved:
            sink_function = self.project.kb.functions[handler._sink_function_addr]
            self.exclude_future_traces(dep, sink_function)

    def post_analysis(
        self, dep: ReachingDefinitionsAnalysis, handler: HandlerBase
    ) -> bool:
        """
        :param dep: Completed RDA
        :param handler: Handler object
        :return: Whether results have been fully resolved
        """
        return False

    def contains_external(self, rda: ReachingDefinitionsAnalysis, unresolved_closures):
        main_func = self.project.kb.functions.function(name="main")
        has_main = main_func is not None and rda.subject.content.includes_function(
            main_func.addr
        )
        if has_main:
            return True

        for closures in unresolved_closures.values():
            for closure in closures:
                external_defs = closure.handler.analyzed_list[0].definitions
                for sink_atom in closure.handler._sink_atoms:
                    if any(
                        defn in closure.sink_trace.closures[sink_atom]
                        for defn in external_defs
                    ):
                        return True

    def vulnerable_sinks_from_call_trace(
        self, handler: HandlerBase
    ) -> Dict[StoredFunction, LiveDefinitions]:
        vulnerable_sinks = {}
        sink_function = self.project.kb.functions[handler._sink_function_addr]
        for ct in handler.analyzed_list:
            if ct.function.addr != sink_function.addr:
                continue
            self.log.debug("Checking %s for closure", ct)
            if not self.forward_trace:
                final_callsite = ct.subject.content.callsites[0]
                call_tup = (
                    final_callsite.caller_func_addr,
                    final_callsite.callee_func_addr,
                )
                if sink_function in self.trace_dict:
                    if (
                        call_tup in self.trace_dict[sink_function]
                        and ct.code_loc.ins_addr
                        not in self.trace_dict[sink_function][call_tup]["valid_sinks"]
                    ):
                        continue
            vulnerable_sinks[ct] = ct.definitions
        return vulnerable_sinks

    def exclude_future_traces(
        self, rda: ReachingDefinitionsAnalysis, sink_function: Function
    ):
        current_function_address = rda.subject.content.current_function_address()
        self.log.info(
            "Exclude function %#x from future slices since the data dependencies are fully resolved.",
            current_function_address,
        )
        subject_callsites = rda.subject.content.callsites
        self.excluded_functions[sink_function].add(
            (
                current_function_address,
                frozenset(
                    (x.caller_func_addr, x.callee_func_addr) for x in subject_callsites
                ),
            )
        )


def default_parser():
    parser = argparse.ArgumentParser()

    path_group = parser.add_argument_group(
        "Path Args", "Deciding source and result destination"
    )

    run_group = parser.add_argument_group(
        "Running", "Options that modify how mango runs"
    )

    output_group = parser.add_argument_group(
        "Output", "Options to increase or modify output"
    )

    path_group.add_argument(dest="bin_path", help="Binary to analyze.")
    path_group.add_argument(
        "--results",
        dest="result_path",
        default=Path("mango_results").resolve(),
        help="Where to store the results of the analysis.",
    )

    run_group.add_argument(
        "--min-depth",
        default=1,
        type=int,
        help="The minimum callstack height the analysis can reach from each sink to consider.",
    )

    run_group.add_argument(
        "--max-depth",
        default=1,
        type=int,
        help="The maximum callstack height the analysis can reach from each sink.",
    )

    run_group.add_argument(
        "--source",
        dest="source_function",
        default="main",
        type=str,
        help="Use the specified function source",
    )

    output_group.add_argument(
        "--disable-progress",
        dest="disable_progress_bar",
        action="store_true",
        default=False,
        help="Disable CFG progress bar",
    )

    run_group.add_argument(
        "--exclude",
        dest="excluded_functions",
        type=str,
        nargs="+",
        help="List of functions to exclude from analysis",
    )

    run_group.add_argument(
        "--workers",
        dest="workers",
        type=int,
        default=1,
        help="Set amount of workers to run during VRA",
    )

    run_group.add_argument(
        "--ld-paths",
        dest="ld_paths",
        nargs="+",
        help="Run analysis with ld_paths",
    )

    run_group.add_argument(
        "--rda-timeout",
        dest="rda_timeout",
        type=int,
        default=5 * 60,
        help="Run with angr project auto_load_libs = True",
    )

    run_group.add_argument(
        "--full-execution",
        dest="full_exec",
        action="store_true",
        default=False,
        help="Turns off assumed execution",
    )

    run_group.add_argument(
        "--forward-trace",
        dest="forward_trace",
        action="store_true",
        default=False,
        help="Starts from source to sink",
    )

    output_group.add_argument(
        "--loglevel",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        dest="log_level",
        help="Set the logging level",
    )

    output_group.add_argument(
        "--enable-breakpoint",
        dest="enable_breakpoint",
        action="store_true",
        default=False,
        help="Enable breakpoint on error",
    )

    run_group.add_argument(
        "--keyword-dict",
        dest="keyword_dict",
        default=None,
        help="Where to store the results of the analysis.",
    )

    return parser, [path_group, run_group, output_group]
