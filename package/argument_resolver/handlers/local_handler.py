import networkx as nx

from typing import Optional, Tuple, Set, List, Type, Union

from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.analyses.reaching_definitions.reaching_definitions import ReachingDefinitionsAnalysis

from angr.analyses.analysis import AnalysisFactory
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.analyses.reaching_definitions.subject import Subject
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER, OP_BEFORE
from angr.code_location import CodeLocation

from .base import HandlerBase
from argument_resolver.utils.stored_function import StoredFunction

from .nvram import NVRAMHandlers
from .stdio import StdioHandlers
from .stdlib import StdlibHandlers
from .string import StringHandlers
from .unistd import UnistdHandlers

from ..utils.rda import CustomRDA
from ..utils.call_trace_visitor import CallTraceSubject
from .functions import get_constant_function
import time
from collections import deque

LibraryHandler = Union[
    NVRAMHandlers,
    StdioHandlers,
    StdlibHandlers,
    StringHandlers,
    UnistdHandlers,
]


class LocalHandler(HandlerBase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.white_list = []
        self.ReachingDefinitionsAnalysis = AnalysisFactory(self._project, CustomRDA)
        self.triggered = False
        self.external_input = False
        self.external_list = []

    @HandlerBase.tag_parameter_definitions
    def handle_local_function(
            self,
            state: ReachingDefinitionsState,
            current_func: StoredFunction,
            first_run: bool = False,
    ):
        """
        Handles local functions during RDA
        :return: StateChange: bool, state, visited_blocks, dep_graph
        """
        if self._rda.rda_timeout != 0 and self._rda.start_time is not None and (time.time() - self._rda.start_time) > self._rda.rda_timeout:
            raise TimeoutError("RDA Timeout")

        if self.first_run:
            self.first_run = False
            return

        elif self.current_parent is None and not self.taint_trace:
            return

        elif current_func.name == self.call_trace[-2].name and current_func.function.is_simprocedure and self.call_trace[-2].function.is_plt:
            self.call_trace.pop(-1)
            return

        if self.progress_callback and self.current_parent is not None:
            self.progress_callback(self.current_parent.name, hex(self.current_parent.code_loc.ins_addr or self.current_parent.function.addr), current_func.name, hex(current_func.code_loc.ins_addr or current_func.function.addr))

        # Either going one callsite deeper or hit the final sink
        if self.hit_depth_change(current_func):
            self.log.debug("Hit Depth Change at: %s", current_func)
            rda_tuple = self.attempt_reanalysis(current_func)
            if rda_tuple is not None:
                return rda_tuple

        if not current_func.exit_site_addresses and not first_run:
            current_func.handle_ret(current_func.state)
            return current_func.success_tuple

        should_analyze, next_subject, analyzed_idx = self.should_run_analysis(current_func)

        if should_analyze:
            if analyzed_idx:
                self.analyzed_list[analyzed_idx] = current_func
            else:
                self.analyzed_list.append(current_func)
            if self.forward_trace:
                for idx, x in enumerate(self.white_list.copy()):
                    if x.code_loc.ins_addr == current_func.code_loc.ins_addr:
                        self.white_list.pop(idx)
                        break

            current_func.save_constant_arg_data(state)
            rda_tup = self.run_rda(current_func, next_subject, first_run=first_run)
            if self.call_stack[-1] == current_func:
                self.call_stack.pop()
            return rda_tup

        current_func.handle_ret()
        return current_func.success_tuple

    def generate_taint_list(self, stored_func: StoredFunction):
        white_list = self.generate_whitelist(stored_func)[0]
        self.white_list += white_list
        stored_func.save_constant_arg_data(stored_func.state)
        analyzed = set()
        analyze_queue = [(x, 0) for x in white_list.copy()]
        for x in white_list:
            x.save_closures()
        while analyze_queue:
            func, depth = analyze_queue.pop()
            if func in analyzed or depth > 2:
                continue

            analyzed.add(func)

            if func.function.addr in {stored_func.function.addr, self.current_parent.function.addr if self.current_parent is not None else 0}:
                continue

            if self.is_handled(func.name):
                continue

            new_graph = DepGraph()
            old_graph = func.state.dep_graph
            func.state.analysis._dep_graph = new_graph
            last_idx = len(self.call_trace)
            self.run_rda(func, CallTraceSubject(func.subject.content, func.function), first_run=False)

            old_parent = self.current_parent
            self.current_parent = func

            new_trace = self.call_trace[last_idx:]
            new_trace.insert(0, func)
            old_trace = self.call_trace[:last_idx]
            starting_idx = 0
            while starting_idx < len(old_trace):
                for idx in range(starting_idx, len(old_trace)):
                    if old_trace[idx] == func:
                        old_trace = old_trace[:idx + 1] + new_trace[1:] + old_trace[idx + 1:]
                        starting_idx = idx + len(new_trace)
                        break
                else:
                    break

            self.call_trace = new_trace

            for defn in func.definitions:
                if defn not in new_graph.graph:
                    for node in [x for x in new_graph.graph.nodes() if
                                 x.codeloc.ins_addr == func.code_loc.ins_addr and x.atom == defn.atom]:
                        new_graph.add_edge(defn, node)
            white_list = self.generate_whitelist(func)[0]
            white_list.remove(func)
            for x in white_list:
                x.save_closures()
            analyze_queue.extend([(x, depth + 1) for x in white_list])
            self.white_list += white_list
            self.current_parent = old_parent
            self.call_trace = old_trace
            old_graph.graph.add_nodes_from(new_graph.graph.nodes())
            old_graph.graph.add_edges_from(new_graph.graph.edges())

            func.state.analysis._dep_graph = old_graph

    def should_run_analysis(self, stored_func: StoredFunction) -> Tuple[bool, Subject, Optional[int]]:
        if self.taint_trace:
            if any(x.code_loc.ins_addr == stored_func.code_loc.ins_addr for x in self.call_stack):
                return False, stored_func.subject, None
            self.log.debug("Tainting: %s", stored_func)
            if stored_func.function.addr == stored_func.subject.content.target:
                self.generate_taint_list(stored_func)

            if any(x.caller_func_addr == stored_func.function.addr for x in stored_func.subject.content.callsites) and not any(x.function.addr == stored_func.function.addr for x in self.call_stack):
                self.call_stack.append(stored_func)
                return True, stored_func.subject, None
            else:
                return False, stored_func.subject, None

        if not self.assumed_execution:
            self.log.debug("Analyzing %s", stored_func)
            if hasattr(self, f"handle_{stored_func.function.name}"):
                return True, CallTraceSubject(stored_func.subject.content, self.current_parent.function), None
            else:
                return True, CallTraceSubject(stored_func.subject.content, stored_func.function), None

        white_list_func = [x for x in self.white_list if x.code_loc.ins_addr == stored_func.code_loc.ins_addr]
        if white_list_func:
            try:
                analyzed_idx = self.analyzed_list.index(white_list_func[0])
            except ValueError:
                analyzed_idx = None
            if any(x.code_loc.ins_addr == stored_func.code_loc.ins_addr for x in self.call_stack):
                self.log.debug("Avoiding Recursion %s", stored_func)
                return False, stored_func.subject, None

            self.log.debug("Analyzing %s", stored_func)
            if hasattr(self, f"handle_{stored_func.function.name}"):
                if self.current_parent is None:
                    cfg = self._project.kb.cfgs.get_most_accurate()
                    node = cfg.get_any_node(stored_func.code_loc.block_addr)
                    func = self._project.kb.functions[node.function_address]
                else:
                    func = self.current_parent.function
                return True, CallTraceSubject(stored_func.subject.content, func), analyzed_idx
            else:
                return True, CallTraceSubject(stored_func.subject.content, stored_func.function), None
        self.log.debug("Skipping %s", stored_func)
        return False, stored_func.subject, None

    def is_handled(self, function_name: str) -> bool:
        return hasattr(self, f"handle_{function_name.replace('__isoc99_', '')}")

    def run_rda(self, stored_func: StoredFunction, subject: Subject, is_reanalysis=False, first_run=False):
        old_rda = self._rda
        prev_parent = self.current_parent

        visited_blocks = stored_func.visited_blocks
        dep_graph = stored_func.state.dep_graph
        if len(self.get_trimmed_callstack(stored_func)) >= self.max_local_call_depth:
            return stored_func.failed_tuple

        constant_func = get_constant_function(stored_func.name)
        if constant_func is not None:
            self.call_stack.append(stored_func)
            constant_func.set_cc(self._calling_convention_resolver.get_cc(stored_func.name))
            return constant_func.constant_handler(stored_func.state, stored_func)

        elif not is_reanalysis and self.is_handled(stored_func.name):
            stored_func._data.effects = []
            return self.handle_simprocedure_function(stored_func, stored_func.state, visited_blocks)

        observation_points = self._rda._observation_points | {("insn", x, OP_AFTER) for x in stored_func.exit_site_addresses}

        rda = self.ReachingDefinitionsAnalysis(
            kb=self._rda.kb,
            init_state=stored_func.state,
            observation_points=observation_points,
            subject=subject,
            function_handler=self,
            start_time=self._rda.start_time,
            rda_timeout=self._rda.rda_timeout,
            visited_blocks=visited_blocks,
            dep_graph=dep_graph,
            prev_observed=self._rda.observed_results,
            is_reanalysis=is_reanalysis,
        )

        rda_tuple = None
        if not first_run and not is_reanalysis and not hasattr(self, f"handle_{stored_func.function.name}") and not self._rda.should_abort:
            if not self.assumed_execution and stored_func.function.addr not in {x.caller_func_addr for x in subject.content.callsites}:
                prev_white_list = self.white_list.copy()
                self.white_list.clear()
                rda_tuple = self.attempt_reanalysis(stored_func)
                self.white_list = prev_white_list

        if rda_tuple is None:
            self._update_old_rda(stored_func.state, old_rda, rda, stored_func)
            rda_tuple = (True, stored_func.state, rda.visited_blocks, dep_graph)

        self.current_parent = prev_parent

        if not hasattr(self, f"handle_{stored_func.function.name}") and not is_reanalysis:
            stored_func.handle_ret(rda_tuple[1])
        return rda_tuple

    def _update_old_rda(self,
                        state: ReachingDefinitionsState,
                        old_rda: ReachingDefinitionsAnalysis,
                        rda: ReachingDefinitionsAnalysis,
                        stored_func: StoredFunction):

        self.hook(old_rda)
        old_rda.observed_results.update(rda.observed_results)
        old_rda.function_calls.update(rda.function_calls)
        old_rda._dep_graph = rda.dep_graph
        state.analysis = old_rda
        try:
            old_sp = state.registers.load(
                state.arch.sp_offset, size=state.arch.bytes
            )
            all_exit_states = [rda.model.observed_results.get(("node", x, OP_AFTER), None) for x in stored_func.exit_site_addresses]
            all_exit_states = [x for x in all_exit_states if x is not None]
            if len(all_exit_states) > 0:
                merged_state = all_exit_states[0]
                if len(all_exit_states) > 1:
                    merged_state = merged_state.merge(all_exit_states[1:])
                state.live_definitions = merged_state
                state.registers.store(state.arch.sp_offset, old_sp, size=state.arch.bytes)
        except AttributeError:
            pass

    def get_trimmed_callstack(self, stored_func):
        if self.current_parent is None:
            return []

        if any(x.caller_func_addr == self.current_parent.function.addr for x in stored_func.subject.content.callsites):
            return []
        idx = 0
        for idx, func in enumerate(self.call_stack[::-1]):
            if any(x.caller_func_addr == func.function.addr for x in stored_func.subject.content.callsites):
                break
        return [x.function.addr for x in self.call_stack[len(self.call_stack)-idx:]]

    def handle_simprocedure_function(self,
                                     stored_func: StoredFunction,
                                     state: ReachingDefinitionsState,
                                     visited_blocks: set):

        handler = getattr(self, f"handle_{stored_func.function.name.replace('__isoc99_', '')}", None)
        self.call_stack.append(stored_func)
        if handler is None:
            return stored_func.failed_tuple
        else:
            analyzed, new_state = handler(state, stored_func)
            #HandlerBase._balance_stack_before_returning(new_state, stored_func)
            if not analyzed:
                return stored_func.failed_tuple

            return True, new_state, visited_blocks, new_state.dep_graph

    def attempt_reanalysis(self, stored_func: StoredFunction) -> Optional[Tuple]:
        if not self.forward_trace and stored_func.function.addr in {x.caller_func_addr for x in stored_func.subject.content.callsites}:
            return None

        if any(x.function.addr == stored_func.function.addr for x in self.call_stack[:-1]):
            return None

        if self.white_list or not self.assumed_execution:
            if any(x not in self.analyzed_list for x in self.white_list):
                return None

        self.white_list, in_subject = self.generate_whitelist(stored_func)
        # Re-run analysis on current parent function but with the whitelist this time
        if set(self.white_list) < set(self.analyzed_list):
            self.white_list = []
            return None

        if set(self.white_list) == {stored_func}:
            return None

        if len(self.white_list) > 0:
            resume_func, max_index = self.find_resume_function()
            self.call_trace = self.call_trace[:len(self.call_trace) - max_index]

            new_subject = CallTraceSubject(self.current_parent.subject.content, self.current_parent.function)
            new_subject.visitor.mark_nodes_as_visited({block for block in resume_func.visited_blocks if block.addr != resume_func.code_loc.block_addr})
            resume_func.state._subject = new_subject
            self.log.debug("Re-analyzing %s from %s", self.current_parent, resume_func)

            if resume_func == self.current_parent:
                for callsite in new_subject.content.callsites:
                    if callsite.caller_func_addr == self.current_parent.function.addr:
                        callsite.block_addr = stored_func.code_loc.block_addr

                resume_addr = resume_func.function.addr
            else:
                resume_addr = resume_func.code_loc.block_addr

            try:
                old_state = self._rda.get_reaching_definitions_by_node(resume_addr, OP_BEFORE)
                resume_func.state.live_definitions = old_state
            except KeyError:
                try:
                    arch = resume_func.state.arch
                    old_sp = self.call_trace[-2].state.registers.load(arch.sp_offset, size=arch.bytes)
                    resume_func.state.registers.store(arch.sp_offset, old_sp, size=arch.bytes)
                except (AssertionError, IndexError):
                    pass
            rda_tup = self.run_rda(resume_func, new_subject, is_reanalysis=True)
            self._rda.abort()
            return rda_tup

        return None

    def find_resume_function(self) -> Tuple[StoredFunction, int]:
        """
        Go through the white list of functions and find the earliest point to resume from.
        Also rewind the call_trace until that point
        :return:
        """
        reversed_trace = self.call_trace[::-1]
        idx = reversed_trace.index(self.current_parent)
        reversed_trace = reversed_trace[:idx+1]
        max_index = -1
        resume_func = None
        for func in self.white_list:
            try:
                index = reversed_trace.index(func)
                if index > max_index:
                    max_index = index
                    resume_func = func
            except ValueError:
                pass

        return resume_func, max_index

    def hit_depth_change(self, stored_func: StoredFunction) -> bool:
        """
        Determines if a depth change occurs as we descend deeper into the calltrace
        :param stored_func:
        :return: has_changed: bool
        """
        assert isinstance(self._rda.subject, CallTraceSubject)
        if self.taint_trace:
            return False

        if stored_func.function.addr == self._sink_function_addr:
            all_constant = True
            for sink_atom in self._sink_atoms:
                if sink_atom not in stored_func.constant_data:
                    all_constant = False
                elif stored_func.constant_data[sink_atom] is None or any(x is None for x in stored_func.constant_data[sink_atom]):
                    all_constant = False
            if all_constant:
                return False

        if stored_func.function.addr != self._sink_function_addr and any(x.code_loc.ins_addr == stored_func.code_loc.ins_addr for x in self.analyzed_list):
            return False

        for callsite in stored_func.subject.content.callsites:
            if self.current_parent is None:
                continue

            if callsite.caller_func_addr == self.current_parent.function.addr \
                    and callsite.callee_func_addr == stored_func.function.addr:
                if callsite.block_addr is None:
                    return True
                if callsite.block_addr == stored_func.code_loc.block_addr:
                    callsite.block_addr = None
                    return True
        return False

    def generate_whitelist(self, stored_func: StoredFunction) -> Tuple[List[StoredFunction], bool]:
        if stored_func.function.addr == self._sink_function_addr:
            target_defns = {defn for atom in self._sink_atoms for defn in stored_func.state.get_definitions(atom)}
            in_subject = True
        else:
            target_defns = stored_func.definitions
            in_subject = stored_func.function.addr == stored_func.subject.content.target
            in_subject |= any(stored_func.function.addr == x.caller_func_addr for x in stored_func.subject.content.callsites)

        if in_subject:
            graph = stored_func.state.dep_graph
        else:
            graph = self.call_trace[-1].state.dep_graph

        # white_list = [x[0] for x in self.get_dependent_definitions(graph, stored_func, target_defns=target_defns, in_subject=in_subject)]
        white_list = self.get_dependent_definitions(graph, stored_func, target_defns=target_defns, in_subject=in_subject)
        if not white_list or white_list == [self.current_parent]:
            white_list.append(stored_func)

        return white_list, in_subject

    @staticmethod
    def bfs_with_stop_nodes(graph, start_nodes, stop_nodes):
        visited = set()
        queue = deque(start_nodes)

        while queue:
            current_node = queue.popleft()

            if current_node in stop_nodes:
                continue  # Skip and do not explore from this node

            if current_node not in visited:
                visited.add(current_node)
                if current_node in graph:
                    neighbors = list(graph[current_node])
                    queue.extend(neighbors)

        return visited

    def get_dependent_definitions(self, graph: DepGraph, stored_func: StoredFunction, target_defns: Set[Definition], in_subject) -> List[StoredFunction]:
        """
        Recursively get all definitions that our target depends on
        :param stored_func:
        :param target_atoms:
        :return:
        """

        # Get all root nodes of the dependency tree based on the target definitions

        if self.current_parent is not None:
            parent_idx = self.call_trace.index(self.current_parent)
        else:
            parent_idx = 0
        truncated_trace = self.call_trace[parent_idx:]
        dependent_defns: Set[Definition] = set()

        # Get all nodes reachable from the root nodes
        func_queue = [stored_func]
        white_list = []
        while func_queue:
            root_defns: Set[Definition] = set()
            func = func_queue.pop(0)
            white_list.append(func)

            if func == stored_func:
                if in_subject:
                    for defn in target_defns:
                        closure_graph = graph.transitive_closure(defn)
                        root_defns |= {node for node in closure_graph if closure_graph.in_degree[node] == 0}
                else:
                    root_defns = target_defns
            else:
                for defn in func.definitions:
                    closure_graph = graph.transitive_closure(defn)
                    root_defns |= {node for node in closure_graph if closure_graph.in_degree[node] == 0}

            new_defns = set()
            for defn in {x for x in root_defns if x in graph.graph}:
                if defn not in dependent_defns:
                    try:
                        new_defns |= set(nx.dfs_preorder_nodes(graph.graph, source=defn))
                    except KeyError:
                        all_nodes = set(graph.graph.nodes())
                        remove_edges = set()
                        remove_nodes = set()
                        for u, v in graph.graph.edges:
                            if u not in all_nodes:
                                remove_nodes.add(u)
                                remove_edges.add((u, v))
                            if v not in all_nodes:
                                remove_nodes.add(v)
                                remove_edges.add((u, v))
                        graph.graph.remove_nodes_from(remove_nodes)
                        graph.graph.remove_edges_from(remove_edges)
                        new_defns |= set(nx.dfs_preorder_nodes(graph.graph, source=defn))
            dependent_defns |= new_defns

            valid_funcs = []
            for t_f in truncated_trace.copy():
                if t_f in white_list:
                    continue
                if any(d in new_defns for d in t_f.definitions | t_f.return_definitions) and t_f.function is not None:
                    valid_funcs.append(t_f)
                    truncated_trace.remove(t_f)

            func_queue.extend(valid_funcs)

        return white_list

    @staticmethod
    def get_nodes_to_revisit(pred: StoredFunction, desc: StoredFunction):
        earlier_blocks = pred._visited_blocks
        earlier_blocks.discard(next(x for x in earlier_blocks if x.addr == pred.code_loc.block_addr))
        revisit_nodes = desc._visited_blocks - pred._visited_blocks
        return revisit_nodes

    def local_func_wrapper(self, function, state, code_loc):
        return self.handle_local_function(state,
                                          function.addr,
                                          call_stack=[],
                                          max_local_call_depth=self._rda._maximum_local_call_depth,
                                          visited_blocks=self._rda.visited_blocks,
                                          dep_graph=state.dep_graph,
                                          codeloc=code_loc,
                                          )

    def handle_external_function_name(
        self,
        state: ReachingDefinitionsState,
        ext_func_name: str,
        src_codeloc: Optional[CodeLocation] = None,
    ) -> Tuple[bool, ReachingDefinitionsState]:
        handler_name = f"handle_{ext_func_name}"
        function = self._project.kb.functions[ext_func_name]
        if ext_func_name and hasattr(self, handler_name):
            if function.is_simprocedure:
                analyzed, state, _, _ = self.local_func_wrapper(function, state, src_codeloc)
                return analyzed, state
            else:
                return getattr(self, handler_name)(state, src_codeloc)
        else:
            self.log.debug("No handler for external function %s(), falling back to generic handler", ext_func_name)
            if self.call_trace[-1].function.name == function.name:
                return False, state
            analyzed, state, _, _ = self.local_func_wrapper(function, state, src_codeloc)
            return analyzed, state


def handler_factory(
        handlers: Optional[List[Type[LibraryHandler]]] = None,
) -> Type[LocalHandler]:
    """
    Generate a `Handler` inheriting from the given handlers.

    :param handlers: The list of library handlers to inherit behavior from.
    :return: A `FunctionHandler` to be used during an analysis.
    """
    handlers = handlers or []
    handler_cls = type("Handler", (LocalHandler, *handlers), {})
    return handler_cls
