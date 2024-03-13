from typing import NamedTuple

from angr.analyses import ReachingDefinitionsAnalysis

from .stored_function import StoredFunction

class SkeletonClosure:

    def __init__(self, closure):
        self.callsites = Closure._get_callsites(closure)
        self.code_loc = closure.sink_trace.code_loc
        self.sink_addr = closure.sink_trace.function.addr
        self.call_stack_len = len(closure.sink_trace.call_stack)
        self.hash = hash(closure)

    def __lt__(self, other):
        if isinstance(other, Closure):
            if not self.sink_addr == other.sink_trace.function.addr:
                return False
            closure_callsites = Closure._get_callsites(other)
            call_stack_len = len(other.sink_trace.call_stack)

        elif isinstance(other, SkeletonClosure):
            closure_callsites = other.callsites
            call_stack_len = other.call_stack_len

        else:
            raise ValueError(f"Cannot compare SkeletonClosure and {other.__class__.__name__}")

        if not (self.callsites < closure_callsites):
            return False

        return self.call_stack_len < call_stack_len

    def __gt__(self, other):
        if isinstance(other, Closure):
            if not self.sink_addr == other.sink_trace.function.addr:
                return False
            closure_callsites = Closure._get_callsites(other)
            call_stack_len = len(other.sink_trace.call_stack)

        elif isinstance(other, SkeletonClosure):
            closure_callsites = other.callsites
            call_stack_len = other.call_stack_len

        else:
            raise ValueError(f"Cannot compare SkeletonClosure and {other.__class__.__name__}")

        if not (self.callsites > closure_callsites):
            return False

        return self.call_stack_len > call_stack_len

    def __hash__(self):
        return self.hash

    def __eq__(self, other):
        return hash(self) == hash(other)


class Closure(NamedTuple):
    sink_trace: StoredFunction
    rda: ReachingDefinitionsAnalysis
    handler: "HandlerBase"

    def __lt__(self, other):
        self._type_check(other)
        if not self.sink_trace.function == other.sink_trace.function:
            return False

        if self.compare_callsites(other) != -1:
            return False

        return self.sink_trace.call_stack < other.sink_trace.call_stack

    def __gt__(self, other):
        self._type_check(other)
        if not self.sink_trace.function == other.sink_trace.function:
            return False

        if self.compare_callsites(other) != 1:
            return False

        return self.sink_trace.call_stack > other.sink_trace.call_stack

    def __eq__(self, other):
        self._type_check(other)
        return hash(self) == hash(other)

    def compare_callsites(self, other):
        callsites = self._get_callsites(self)
        other_callsites = self._get_callsites(other)

        if callsites == other_callsites:
            return 0

        if callsites < other_callsites:
            return -1

        if callsites > other_callsites:
            return 1

        return None

    @staticmethod
    def _get_callsites(closure):
        callsites = set()
        for callsite in closure.sink_trace.subject.content.callsites:
            callsites.add(callsite.caller_func_addr)
            callsites.add(callsite.callee_func_addr)

        return callsites

    def get_call_locations(self):
        callsites = {
            x.caller_func_addr for x in self.sink_trace.subject.content.callsites
        }

        trace_1_idx = self.handler.analyzed_list.index(self.sink_trace)
        call_locs = {
            x.code_loc.ins_addr or x.code_loc.block_addr
            for x in self.handler.analyzed_list[:trace_1_idx]
            if x.function.addr in callsites
        }
        return call_locs

    @staticmethod
    def _type_check(other):
        if not isinstance(other, Closure):
            raise ValueError(f"Cannot compare Closure and {other.__class__.__name__}")
