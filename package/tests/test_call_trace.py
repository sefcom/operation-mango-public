from unittest import TestCase

import networkx

from angr.analyses.reaching_definitions.call_trace import CallSite

from argument_resolver.utils.call_trace import traces_to_sink


class MockFunction:
    def __init__(self, _addr):
        self.addr = _addr


class TestCallTrace(TestCase):
    def test_traces_to_sink(self):
        f0, f1, f2 = [MockFunction(i) for i in range(0, 3)]
        sink = MockFunction(0x42)

        # Represent the following callgraph:
        # 0 -> 1 -> 2 -> 0x42
        callgraph = networkx.MultiDiGraph(
            [
                (f0.addr, f1.addr),
                (f1.addr, f2.addr),
                (f2.addr, sink.addr),
            ]
        )

        traces = list(traces_to_sink(sink, callgraph, 3, {}))
        expected_first_callsites = [
            CallSite(2, None, 0x42),
            CallSite(1, None, 2),
            CallSite(0, None, 1),
        ]

        self.assertEqual(len(traces), 1)

        self.assertEqual(traces[0].target, 0x42)
        self.assertListEqual(traces[0].callsites, expected_first_callsites)

    def test_traces_to_sink_recovers_everything_when_given_a_super_big_depth(self):
        f0, f1, f2 = [MockFunction(i) for i in range(0, 3)]
        sink = MockFunction(0x42)

        # Represent the following callgraph:
        # 0 -> 1 -> 2 -> 0x42
        callgraph = networkx.MultiDiGraph(
            [
                (f0.addr, f1.addr),
                (f1.addr, f2.addr),
                (f2.addr, sink.addr),
            ]
        )

        traces = list(traces_to_sink(sink, callgraph, 9999, {}))

        expected_first_callsites = [
            CallSite(2, None, 0x42),
            CallSite(1, None, 2),
            CallSite(0, None, 1),
        ]

        self.assertEqual(len(traces), 1)

        self.assertEqual(traces[0].target, 0x42)
        self.assertListEqual(traces[0].callsites, expected_first_callsites)

    def test_traces_to_sink_recover_all_the_traces_flowing_into_a_sink(self):
        f0, f1, f2, f3 = [MockFunction(i) for i in range(0, 4)]
        sink = MockFunction(0x42)

        # Represent the following callgraph:
        # 0 -> 1 -> 2 -> 0x42, 3 -> 0x42
        callgraph = networkx.MultiDiGraph(
            [
                (f0.addr, f1.addr),
                (f1.addr, f2.addr),
                (f2.addr, sink.addr),
                (f3.addr, sink.addr),
            ]
        )

        traces = list(traces_to_sink(sink, callgraph, 3, {}))
        traces.sort(key=lambda x: x.callsites[0].caller_func_addr)

        expected_first_callsites = [
            CallSite(2, None, 0x42),
            CallSite(1, None, 2),
            CallSite(0, None, 1),
        ]
        expected_second_callsites = [CallSite(3, None, 0x42)]

        self.assertEqual(len(traces), 2)
        self.assertEqual(traces[0].target, 0x42)
        self.assertListEqual(traces[0].callsites, expected_first_callsites)
        self.assertEqual(traces[1].target, 0x42)
        self.assertListEqual(traces[1].callsites, expected_second_callsites)
