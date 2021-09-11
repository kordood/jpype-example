import logging

import MyConcurrentHashMap
import PredecessorShorteningMode
import ZeroedFlowFunctions
import Pair
import ConcurrentHashMap
import AlwaysShorten, ShortenIfEqual

from .pathedge import PathEdge

l = logging.getLogger(name=__name__)


class IFDSSolver:

    PredecessorShorteningMode = {'NeverShorten': 0,
                                 'ShortenIfEqual': 1,
                                 'AlwaysShorten': 2
                                 }

    def __init__(self, tabulation_problem, solver_id):

        # self.DEFAULT_CACHE_BUILDER = CacheBuilder.newBuilder().concurrencyLevel(multiprocessing.cpu_count())
        # .initialCapacity(10000).softValues()
        self.solver_id = solver_id
        self.jump_functions = MyConcurrentHashMap()
        self.end_summary = MyConcurrentHashMap()
        self.incoming = MyConcurrentHashMap()

        self.propagation_count = None
        self.ff_cache = None
        self.shortening_mode = PredecessorShorteningMode.NeverShorten

        self.max_join_point_abstractions = -1

        self.memory_manager = None
        # self.notification_listeners = hash()
        self.kill_flag = None

        self.max_callees_per_call_site = 75
        self.max_abstraction_path_length = 100
        self.initial_seeds = tabulation_problem.initial_seeds()
        self.follow_returns_past_seeds = tabulation_problem.follow_returns_past_seeds()
        self.zero_value = tabulation_problem.zero_value()
        self.icfg = tabulation_problem.interprocedural_cfg()
        self.flow_functions = ZeroedFlowFunctions(tabulation_problem.flowFunctions(), self.zero_value) \
            if tabulation_problem.auto_add_zero() else tabulation_problem.flowFunctions()

    def solve(self):
        self.reset()
        self.submit_initial_seeds()

    def submit_initial_seeds(self):
        for seed in self.initial_seeds.entrySet():
            start_point = seed.getKey()
            for val in seed.getValue():
                self.propagate(self.zero_value, start_point, val, None, False)
            self.add_function(PathEdge(self.zero_value, start_point, self.zero_value))

    def propagate(self, source_val, target, target_val, related_call_site, is_unbalanced_return):
        # Set val to memory manager
        if self.memory_manager is not None:
            source_val = self.memory_manager.handle_memory_object(source_val)
            target_val = self.memory_manager.handle_memory_object(target_val)
            if target_val is None:
                return

        # Truncate if path size exceeds
        if 0 <= self.max_abstraction_path_length < target_val.getPathLength():
            return

        edge = PathEdge(source_val, target, target_val)
        existing_val = self.add_function(edge)

        # Check existing value
        if existing_val is not None:
            # Add target value to neighbor in specific case
            if existing_val != target_val:
                if self.memory_manager is None:
                    is_essential = related_call_site is not None and self.icfg.is_call_stmt(related_call_site)
                else:
                    is_essential = self.memory_manager.is_essential_join_point(target_val, related_call_site)

                if self.max_join_point_abstractions < 0 \
                        or existing_val.get_neighbor_count() < self.max_join_point_abstractions \
                        or is_essential:
                    existing_val.add_neighbor(target_val)

        # Process edge
        else:
            active_val = target_val.getActiveCopy()
            if active_val != target_val:
                active_edge = PathEdge(source_val, target, active_val)
                if self.jump_functions.containsKey(active_edge):
                    return
            self.schedule_edge_processing(edge)

    def add_function(self, edge):
        return self.jump_functions.putIfAbsent(edge, edge.d_target)

    def schedule_edge_processing(self, edge):
        if self.kill_flag is not None:
            return

        target = edge.target
        if self.icfg.is_call_stmt(target):
            self.process_call(edge)
        else:
            if self.icfg.is_exit_stmt(target):
                self.process_exit(edge)
            if not self.icfg.get_succs_of( target ).is_empty():
                self.process_normal_flow(edge)

        self.propagation_count += 1

    def path_edge_processing_task(self, edge, solver_id):
        target = edge.target

        # Handle of Procedure (call / exit / normal)
        if self.icfg.is_call_stmt(target):
            self.process_call(edge)
        else:
            if self.icfg.is_exit_stmt(target):
                self.process_exit(edge)
            if not self.icfg.get_succs_of( target ).is_empty():
                self.process_normal_flow(edge)

    def process_call(self, edge):
        d1 = edge.d_source
        n = edge.target
        d2 = edge.d_target
        assert d2 is not None

        return_site_ns = self.icfg.get_return_sites_of_call_at( n )
        callees = self.icfg.get_callees_of_call_at( n )

        if callees is not None and not callees.is_empty():
            if self.max_callees_per_call_site < 0 or callees.size() <= self.max_callees_per_call_site:
                for callee in callees.stream().filter(lambda m: m.isConcrete()):
                    s_called_proc_n = callee    # Have to fix
                    if self.kill_flag is not None:
                        return

                    function = self.flow_functions.get_call_flow_function(n, s_called_proc_n)
                    result = self.compute_call_flow_function(function, d1, d2)

                    if result is not None and not result.is_empty():
                        start_points_of = self.icfg.get_start_points_of( s_called_proc_n )
                        for d3 in result:
                            if self.memory_manager is not None:
                                d3 = self.memory_manager.handle_generated_memory_object(d2, d3)
                            if d3 is None:
                                continue

                            for start_point in start_points_of:
                                self.propagate(d3, start_point, d3, n, False)

                            if not self.add_incoming(s_called_proc_n, d3, n, d1, d2):
                                continue

                            self.apply_end_summary_on_call(d1, n, d2, return_site_ns, s_called_proc_n, d3)

        for return_site_n in return_site_ns:
            call_to_return_flow_function = self.flow_functions.get_call_to_return_flow_function(n, return_site_n)
            result = self.compute_call_to_return_flow_function(call_to_return_flow_function, d1, d2)

            if result is not None and not result.is_empty():
                for d3 in result:
                    if self.memory_manager is not None:
                        d3 = self.memory_manager.handle_generated_memory_object(d2, d3)
                    if d3 is not None:
                        self.propagate(d1, return_site_n, d3, n, False)

    def compute_call_flow_function(self, call_flow_function, d1, d2):
        return call_flow_function.compute_targets(d2)

    def apply_end_summary_on_call(self, d1, n, d2, return_site_ns, s_called_proc_n, d3):
        end_summary = self.end_summary(s_called_proc_n, d3)

        if end_summary is not None and not end_summary.is_empty():
            for entry in end_summary:
                entry_point = entry.getO1()
                d4 = entry.getO2()

                for ret_site_n in return_site_ns:
                    ret_function = self.flow_functions.get_return_flow_function(n, s_called_proc_n, entry_point,
                                                                                ret_site_n)
                    ret_flow_result = self.compute_return_flow_function(ret_function, d3, d4, n, set(d1))

                    if ret_flow_result is not None and not ret_flow_result.is_empty():
                        for d5 in ret_flow_result:
                            if self.memory_manager is not None:
                                d5 = self.memory_manager.handle_generated_memory_object(d4, d5)

                            d5p = d5
                            if self.shortening_mode == AlwaysShorten:
                                if d5p != d2:
                                    d5p = d5p.clone()
                                    d5p.setPredecessor(d2)
                            elif self.shortening_mode == ShortenIfEqual:
                                if d5 == d2:
                                    d5p = d2

                            self.propagate(d1, ret_site_n, d5p, n, False)
            self.on_end_summary_applied(n, s_called_proc_n, d3)

    def on_end_summary_applied(self, n, s_called_proc, d3):
        pass

    def compute_call_to_return_flow_function(self, call_to_return_flow_function, d1, d2):
        return call_to_return_flow_function.compute_targets(d2)

    def process_exit(self, edge):
        n = edge.target
        method_that_needs_summary = self.icfg.get_method_of(n)

        d1 = edge.d_source
        d2 = edge.d_target

        if not self.add_end_summary(method_that_needs_summary, d1, n, d2):
            return

        inc = self.incoming(d1, method_that_needs_summary)

        if inc is not None and not inc.is_empty():
            for entry in inc.entrySet():
                if self.kill_flag is not None:
                    return

                c = entry.getKey()
                caller_side_ds = entry.getValue().keySet()
                for ret_site_c in self.icfg.get_return_sites_of_call_at( c ):
                    ret_function = self.flow_functions.get_return_flow_function(c, method_that_needs_summary, n,
                                                                                ret_site_c)
                    targets = self.compute_return_flow_function(ret_function, d1, d2, c, caller_side_ds)

                    if targets is not None and not targets.is_empty():
                        for d1d2entry in entry.getValue().entrySet():
                            d4 = d1d2entry.getKey()
                            pred_val = d1d2entry.getValue()

                            for d5 in targets:
                                if self.memory_manager is not None:
                                    d5 = self.memory_manager.handle_generated_memory_object(d2, d5)
                                if d5 is None:
                                    continue
                                d5p = d5

                                if self.shortening_mode == AlwaysShorten:
                                    if d5p != pred_val:
                                        d5p = d5p.clone()
                                        d5p.setPredecessor(pred_val)
                                elif self.shortening_mode == ShortenIfEqual:
                                    if d5 == pred_val:
                                        d5p = pred_val
                                self.propagate(d4, ret_site_c, d5p, c, False)

        if self.follow_returns_past_seeds and d1 == self.zero_value and (inc is None or inc.is_empty()):
            callers = self.icfg.get_callers_of( method_that_needs_summary )

            for c in callers:
                for ret_site_c in self.icfg.get_return_sites_of_call_at( c ):
                    ret_function = self.flow_functions.get_return_flow_function(c, method_that_needs_summary, n,
                                                                                ret_site_c)
                    targets = self.compute_return_flow_function(ret_function, d1, d2, c, set(self.zero_value))
                    if targets is not None and not targets.is_empty():
                        for d5 in targets:
                            if self.memory_manager is not None:
                                d5 = self.memory_manager.handle_generated_memory_object(d2, d5)
                            if d5 is not None:
                                self.propagate(self.zero_value, ret_site_c, d5, c, True)

            if callers.is_empty():
                ret_function = self.flow_functions.get_return_flow_function(None, method_that_needs_summary, n, None)
                ret_function.compute_targets(d2)

    def compute_return_flow_function(self, ret_function, d1, d2, call_site, caller_side_ds):
        return ret_function.compute_targets(d2)

    def process_normal_flow(self, edge):
        d1 = edge.d_source
        n = edge.target
        d2 = edge.d_target

        for m in self.icfg.get_succs_of( n ):
            if self.kill_flag is not None:
                return
            flow_function = self.flow_functions.get_normal_flow_function(n, m)
            res = self.compute_normal_flow_function(flow_function, d1, d2)
            if res is not None and not res.is_empty():
                for d3 in res:
                    if self.memory_manager is not None and d2 != d3:
                        d3 = self.memory_manager.handle_generated_memory_object(d2, d3)
                    if d3 is not None:
                        self.propagate(d1, m, d3, None, False)

    def compute_normal_flow_function(self, flow_function, d1, d2):
        return flow_function.compute_targets(d2)

    def end_summary(self, m, d3):
        _map = self.end_summary.get(Pair(m, d3))
        return None if _map is None else _map.keySet()

    def add_end_summary(self, m, d1, e_p, d2):
        if d1 == self.zero_value:
            return True

        summaries = self.end_summary.putIfAbsentElseGet(Pair(m, d1), lambda: MyConcurrentHashMap())     # I don't know
        old_d2 = summaries.putIfAbsent(Pair(e_p, d2), d2)
        if old_d2 is not None:
            old_d2.add_neighbor(d2)
            return False
        return True

    def incoming(self, d1, m):
        _map = self.incoming.get(Pair(m, d1))
        return _map

    def add_incoming(self, m, d3, n, d1, d2):
        summaries = self.incoming.putIfAbsentElseGet(Pair(m, d3), lambda: MyConcurrentHashMap())    # I don't know
        _set = summaries.putIfAbsentElseGet(n, lambda: ConcurrentHashMap())     # I don't know
        return _set.put(d1, d2) is None
    """
    def set_predecessor_shortening_mode(self, mode):
        pass

    def set_max_join_point_abstractions(self, max_join_point_abstractions):
        self.max_join_point_abstractions = max_join_point_abstractions

    def set_memory_manager(self, memory_manager):
        self.memory_manager = memory_manager

    def get_memory_manager(self):
        return self.memory_manager

    def force_terminate(self, reason):
        self.kill_flag = reason
        self.executor.interrupt()
        self.executor.shutdown()

    def is_terminated(self):
        return self.kill_flag is not None or self.executor.isFinished()

    def is_killed(self):
        return self.kill_flag is not None

    def reset(self):
        self.kill_flag = None

    def add_status_listener(self, listener):
        self.notification_listeners.add(listener)

    def get_termination_reason(self):
        return self.kill_flag

    def set_max_callees_per_call_site(self, max_callees_per_call_site):
        self.max_callees_per_call_site = max_callees_per_call_site

    def set_max_abstraction_path_length(self, max_abstraction_path_length):
        self.max_abstraction_path_length = max_abstraction_path_length
        """
