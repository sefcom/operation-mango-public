import networkx as nx


class GraphHelper:
    """
    Helpful class for displaying Dependency Graph
    """

    @staticmethod
    def find_subgraph_from_defn(graph, sink):
        source_nodes = [x for x in graph if graph.in_degree(x) == 0]
        final_graph = None
        for source_node in source_nodes:
            g = nx.bfs_tree(graph, source_node)
            if sink not in g:
                continue

            if final_graph is None:
                final_graph = g
            else:
                final_graph = nx.compose(final_graph, g)
        return final_graph


    @staticmethod
    def calculate_node_depth(graph, depth=0, node_depth=None):
        if node_depth is None:
            node_depth = {x: 0 for x in graph if graph.in_degree(x) == 0}

        for node in [k for k, v in node_depth.items() if v == depth]:
            for pred in graph.predecessors(node):
                if pred not in node_depth:
                    node_depth[pred] = depth - 1
                    GraphHelper.calculate_node_depth(
                        graph, depth=depth - 1, node_depth=node_depth
                    )
            for succ in graph.successors(node):
                if succ not in node_depth:
                    node_depth[succ] = depth + 1
                    GraphHelper.calculate_node_depth(
                        graph, depth=depth + 1, node_depth=node_depth
                    )
        return node_depth


    @staticmethod
    def show_graph(graph, defns=None):
        import matplotlib.pyplot as plt

        # g = Utils._find_subgraph_from_defn(graph, sink)
        if defns is None:
            defns = set()
        depth_by_node = GraphHelper.calculate_node_depth(graph)
        node_depth = {}
        for n in depth_by_node:
            depth = depth_by_node[n]
            if depth not in node_depth:
                node_depth[depth] = []
            node_depth[depth].append(n)

        max_width = 1
        max_height = 1
        height_step = max_height / len(node_depth)
        pos = {}
        for d in sorted(node_depth):
            width_step = max_width / (len(node_depth[d]) + 1)
            cur_step = width_step
            for node in sorted(
                    node_depth[d], key=lambda x: len(nx.descendants(graph, x)), reverse=True
            ):
                pos[node] = (cur_step, max_height - (d * height_step))
                cur_step += width_step
        labels = {}
        colors = []
        for node in graph.nodes():
            if node not in pos:
                pos[node] = (1, 1)
            labels[node] = node
            if node in defns:
                colors.append("orange")
            elif graph.in_degree(node) == 0:
                colors.append("green")
            elif graph.out_degree(node) == 0:
                colors.append("red")
            else:
                colors.append("blue")

        nx.draw(graph, pos=pos, labels=labels, font_size=8, node_color=colors)
        plt.show()
