from typing import List, Tuple, Optional, Set

from angr.block import BlockNode
from angr.utils.graph import GraphUtils
from angr.analyses.forward_analysis.visitors.graph import GraphVisitor, NodeType
from angr.analyses.reaching_definitions.call_trace import CallTrace
from angr.analyses.reaching_definitions.subject import Subject, SubjectType
from angr.utils.graph import dfs_back_edges


class CallTraceSubject(Subject):
    def __init__(self, trace: CallTrace, func):
        self._content = trace
        self._visitor = FunctionGraphVisitor(func)
        self._type = SubjectType.CallTrace
        self._cc = func.calling_convention

    @property
    def visitor(self) -> "FunctionGraphVisitor":
        return self._visitor

    def copy(self):
        clone = CallTraceSubject(self._content, self._visitor.function)
        clone._visitor._sorted_nodes = self._visitor._sorted_nodes.copy()
        clone._visitor._worklist = self._visitor._worklist.copy()
        clone._visitor._nodes_set = self._visitor._nodes_set.copy()
        clone._visitor._node_to_index = self._visitor._node_to_index.copy()
        clone._visitor._reached_fixedpoint = self._visitor._reached_fixedpoint.copy()
        clone._visitor._back_edges_by_src = self._visitor._back_edges_by_src.copy()
        clone._visitor._back_edges_by_dst = self._visitor._back_edges_by_dst.copy()
        clone._visitor._pending_nodes = self._visitor._pending_nodes.copy()

        return clone


class FunctionGraphVisitor(GraphVisitor):
    """
    :param knowledge.Function func:
    """

    def __init__(self, func, graph=None):
        super().__init__()
        self.function = func

        if graph is None:
            self.graph = self.function.graph
        else:
            self.graph = graph

        self.reset()

    def mark_nodes_for_revisit(self, blocks: Set[BlockNode]):
        for block in blocks:
            self.revisit_node(block)

    def mark_nodes_as_visited(self, nodes: Set[BlockNode]):
        valid_nodes = {x for x in nodes if x in self._nodes_set}
        for node in valid_nodes:
            self._worklist.remove(node)

    def revisit_successors(self, node: NodeType, include_self=True) -> None:
        super().revisit_successors(node, include_self=include_self)
        #print("WORKLIST", node, self._worklist)

    def successors(self, node):
        return list(self.graph.successors(node))

    def predecessors(self, node):
        return list(self.graph.predecessors(node))

    def next_node(self) -> Optional[NodeType]:
        node = super().next_node()
        while node is not None and node in self._reached_fixedpoint:
            node = super().next_node()
        return node

    def sort_nodes(self, nodes=None):
        sorted_nodes = GraphUtils.quasi_topological_sort_nodes(self.graph)

        if nodes is not None:
            sorted_nodes = [n for n in sorted_nodes if n in set(nodes)]

        return sorted_nodes

    def back_edges(self) -> List[Tuple[NodeType, NodeType]]:
        start_nodes = [node for node in self.graph if node.addr == self.function.addr]
        if not start_nodes:
            start_nodes = [
                node for node in self.graph if self.graph.in_degree(node) == 0
            ]

        if not start_nodes:
            raise NotImplementedError()

        start_node = start_nodes[0]
        return list(dfs_back_edges(self.graph, start_node))