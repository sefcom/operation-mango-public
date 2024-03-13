from typing import List, Set, Tuple

import networkx

from angr.analyses.reaching_definitions.call_trace import CallTrace
from angr.knowledge_plugins.functions import Function
from angr import Project


def _trace_contains_child(parent, child):
    if child[1] is None:
        return parent.includes_function(child[0])
    else:
        parent_set = {
            (x.caller_func_addr, x.callee_func_addr) for x in parent.callsites
        }
        return parent.includes_function(child[0]) and child[1].issubset(parent_set)


# TODO This logic can probably be simplified
def traces_to_sink(
        sink: Function,
        callgraph,
        max_depth: int,
        excluded_functions: Set[Tuple],
) -> Set[CallTrace]:
    """
    Peek into the callgraph and discover all functions reaching the sink within `max_depth` layers of calls.

    :param sink: The function to be reached.
    :param project: The project ot obtain the callgraph from.
    :param max_depth: A bound within to look for transitive predecessors of the sink.
    :param excluded_functions: A set of functions to ignore, and stop the discovery from.

    :return: <CallTrace>s leading to the given sink.
    """
    queue: List[Tuple[CallTrace, int]] = [(CallTrace(sink.addr), 0)]
    starts: Set[CallTrace] = set()

    while queue:
        trace, curr_depth = queue.pop(0)

        if trace.current_function_address() in starts:
            continue

        caller_func_addr = trace.current_function_address()
        callers: Set[int] = set(callgraph.predecessors(caller_func_addr))

        if len(callers) == 0:
            starts |= {trace}

        # remove the functions that we already came across - essentially bypassing recursive function calls - and excluded functions
        if any(_trace_contains_child(trace, ex) for ex in excluded_functions):
            callers = set()

        for caller in callers.copy():
            if trace.includes_function(caller):
                callers.remove(caller)
            if any(caller == ex[0] for ex in excluded_functions if ex[1] is None):
                callers.remove(caller)

        caller_depth = curr_depth + 1
        if caller_depth >= max_depth:
            # reached the depth limit. add them to potential analysis starts
            starts |= {
                trace.step_back(caller_addr, None, caller_func_addr)
                for caller_addr in callers
            }
        else:
            # add them to the queue
            queue.extend([(trace.step_back(caller_addr, None, caller_func_addr), caller_depth)
                          for caller_addr in callers
                          ])

    return starts
