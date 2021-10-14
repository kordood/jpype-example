from copy import copy


class ReachableMethods:

    def __init__(self, graph, entry_points, method_filter=None):
        self.reachables = list()  # Queue
        self.method_set = list()
        self.all_reachables = self.reachables

        self.method_filter = method_filter
        self.cg = graph
        self.add_methods(entry_points)
        self.unprocessed_methods = self.reachables
        self.edge_source = graph.listener() if method_filter is None else method_filter.wrap(graph.listener())

    def add_methods(self, methods):
        for method in methods:
            self.add_method(method)

    def add_method(self, m):
        if self.method_set.append(m):
            self.reachables.append(m)

    def update(self):
        for edge in self.edge_source:
            if edge is not None:
                src_method = edge.src
                if src_method is not None and not edge.is_invalid and src_method in self.method_set:
                    self.add_method(edge.tgt)

        for method in self.unprocessed_methods:
            targets = self.cg.edges_out_of(method)
            if self.method_filter is not None:
                targets = self.method_filter.wrap(targets)

            self.add_methods(targets)

    def listener(self):
        return copy(self.all_reachables)

    def new_listener(self):
        return self.reachables

    def __contains__(self, m):
        return self.method_set.__contains__(m)

    def __len__(self):
        return len(self.method_set)
