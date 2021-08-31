from threading import Thread

import CacheBuilder
import multiprocessing
import logging
import InterruptableExecutor
import MyConcurrentHashMap
import PredecessorShorteningMode
import ZeroedFlowFunctions
import FlowFunctionCache
import math
import Pair
import PathEdge, PathEdgeProcessingTask
import Collections
import ConcurrentHashMap
import SetPoolExecutor
import TimeUnit
import LinkedBlockingQueue
import ThreadFactory

import AlwaysShorten, ShortenIfEqual

l = logging.getLogger(name=__name__)

class IFDSSolver:

    def __init__(self, tabulationProblem, solver_id):

#        self.DEFAULT_CACHE_BUILDER = CacheBuilder.newBuilder().concurrencyLevel(
#            multiprocessing.cpu_count()).initialCapacity(10000).softValues()
        self.solver_id = solver_id
        self.jump_functions = MyConcurrentHashMap()
        self.icfg = None
        self.end_summary = MyConcurrentHashMap()
        self.incoming = MyConcurrentHashMap()
        self.flow_functions = None
        self.initial_seeds = None

        self.propagation_count = None
        self.zero_value = None
        self.ff_cache = None
        self.follow_returns_past_seeds = None
        self.shortening_mode = PredecessorShorteningMode.NeverShorten

        self.max_join_point_abstractions = -1

        self.memory_manager = None
        self.solver_id = None
        self.notification_listeners = hash()
        self.kill_flag = None

        self.max_callees_per_call_site = 75
        self.max_abstraction_path_length = 100
        self.ff_cache = None
        self.flow_functions = self.flow_functions
        self.initial_seeds = tabulationProblem.initial_seeds()
        self.follow_returns_past_seeds = tabulationProblem.follow_returns_past_seeds()

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
        if self.memory_manager != None:
            source_val = self.memory_manager.handleMemoryObject(source_val)
            target_val = self.memory_manager.handleMemoryObject(target_val)
            if target_val == None:
                return

        # Truncate if path size exceeds
        if self.max_abstraction_path_length >= 0 and target_val.getPathLength() > self.max_abstraction_path_length:
            return

        edge = PathEdge(source_val, target, target_val)
        existing_val = self.add_function(edge)

        # Check existing value
        if existing_val != None:
            # Add target value to neighbor in specific case
            if existing_val != target_val:
                if self.memory_manager == None:
                    is_essential = related_call_site != None and self.icfg.isCallStmt(related_call_site)
                else:
                    is_essential = self.memory_manager.isEssentialJoinPoint(target_val, related_call_site)

                if self.max_join_point_abstractions < 0 \
                    or existing_val.getNeighborCount() < self.max_join_point_abstractions \
                    or is_essential:
                    existing_val.addNeighbor(target_val)

        # Process edge
        else:
            active_val = target_val.getActiveCopy()
            if active_val != target_val:
                active_edge = PathEdge(source_val, target, active_val)
                if self.jump_functions.containsKey(active_edge):
                    return
            self.schedule_edge_processing(edge)

    def add_function(self, edge):
        return self.jump_functions.putIfAbsent(edge, edge.factAtTarget())

    def schedule_edge_processing(self, edge):
        # Have to kill?
        if self.kill_flag != None or self.executor.isTerminating() or self.executor.is_terminated():
            return

        self.path_edge_processing_task(edge, self.solver_id)
        self.propagation_count += 1

    def path_edge_processing_task(self, edge, solver_id):
        target = edge.getTarget()

        # Handle of Procedure (call / exit / normal)
        if self.icfg.isCallStmt(target):
            self.process_call(edge)
        else:
            if self.icfg.isExitStmt(target):
                self.process_exit(edge)
            if not self.icfg.getSuccsOf(target).isEmpty():
                self.process_normal_flow(edge)

    def process_call(self, edge):
        d1 = edge.factAtSource()
        n = edge.getTarget()
        d2 = edge.factAtTarget()
        assert d2 != None

        return_site_ns = self.icfg.getReturnSitesOfCallAt(n)
        callees = self.icfg.getCalleesOfCallAt(n)

        if callees != None and not callees.isEmpty():
            if self.max_callees_per_call_site < 0 or callees.size() <= self.max_callees_per_call_site:
                for callee in callees.stream().filter(lambda m: m.isConcrete()):
                    s_called_proc_n = callee # Have to fix
                    if self.kill_flag != None:
                        return

                    function = self.flow_functions.getCallFlowFunction(n, s_called_proc_n)
                    result = self.compute_call_flow_function(function, d1, d2)

                    if result is not None and not result.isEmpty():
                        start_points_of = self.icfg.getStartPointsOf(s_called_proc_n)
                        for d3 in result:
                            if self.memory_manager != None:
                                d3 = self.memory_manager.handleGeneratedMemoryObject(d2, d3)
                            if d3 is None:
                                continue

                            for start_point in start_points_of:
                                self.propagate(d3, start_point, d3, n, False)

                            if not self.add_incoming(s_called_proc_n, d3, n, d1, d2):
                                continue

                            self.apply_end_summary_on_call(d1, n, d2, return_site_ns, s_called_proc_n, d3)

        for return_site_n in return_site_ns:
            call_to_return_flow_function = self.flow_functions.getCallToReturnFlowFunction(n, return_site_n)
            result = self.compute_call_to_return_flow_function(call_to_return_flow_function, d1, d2)

            if result is not None and not result.isEmpty():
                for d3 in result:
                    if self.memory_manager is not None:
                        d3 = self.memory_manager.handleGeneratedMemoryObject(d2, d3)
                    if d3 is not None:
                        self.propagate(d1, return_site_n, d3, n, False)

    def compute_call_flow_function(self, call_flow_function, d1, d2):
        return call_flow_function.compute_targets( d2 )

    def apply_end_summary_on_call(self, d1, n, d2, return_site_ns, s_called_proc_n, d3):
        end_summary = self.end_summary(s_called_proc_n, d3)

        if end_summary is not None and not end_summary.isEmpty():
            for entry in end_summary:
                entry_point = entry.getO1()
                d4 = entry.getO2()

                for ret_site_n in return_site_ns:
                    ret_function = self.flow_functions.getReturnFlowFunction(n, s_called_proc_n, entry_point,
                                                                             ret_site_n)
                    ret_flow_result = self.compute_return_flow_function(ret_function, d3, d4, n,
                                                                        Collections.singleton(d1))

                    if ret_flow_result is not None and not ret_flow_result.isEmpty():
                        for d5 in ret_flow_result:
                            if self.memory_manager is not None:
                                d5 = self.memory_manager.handleGeneratedMemoryObject(d4, d5)

                            d5p = d5
                            if self.shortening_mode == AlwaysShorten:
                                if d5p != d2:
                                    d5p = d5p.clone()
                                    d5p.setPredecessor(d2)
                            elif self.shortening_mode == ShortenIfEqual:
                                if d5.equals(d2):
                                    d5p = d2

                            self.propagate(d1, ret_site_n, d5p, n, False)
            self.on_end_summary_applied(n, s_called_proc_n, d3)

    def on_end_summary_applied(self, n, s_called_proc, d3):
        pass

    def compute_call_to_return_flow_function(self, call_to_return_flow_function, d1, d2):
        return call_to_return_flow_function.compute_targets( d2 )

    def process_exit(self, edge):
        n = edge.getTarget()
        method_that_needs_summary = self.icfg.get_method_of( n )

        d1 = edge.factAtSource()
        d2 = edge.factAtTarget()

        if not self.add_end_summary(method_that_needs_summary, d1, n, d2):
            return

        inc = self.incoming(d1, method_that_needs_summary)

        if inc is not None and not inc.isEmpty():
            for entry in inc.entrySet():
                if self.kill_flag is not None:
                    return

                c = entry.getKey()
                caller_side_ds = entry.getValue().keySet()
                for ret_site_c in self.icfg.getReturnSitesOfCallAt(c):
                    ret_function = self.flow_functions.getReturnFlowFunction(c, method_that_needs_summary, n,
                                                                             ret_site_c)
                    targets = self.compute_return_flow_function(ret_function, d1, d2, c, caller_side_ds)

                    if targets is not None and not targets.isEmpty():
                        for d1d2entry in entry.getValue().entrySet():
                            d4 = d1d2entry.getKey()
                            pred_val = d1d2entry.getValue()

                            for d5 in targets:
                                if self.memory_manager is not None:
                                    d5 = self.memory_manager.handleGeneratedMemoryObject(d2, d5)
                                if d5 is None:
                                    continue
                                d5p = d5

                                if self.shortening_mode == AlwaysShorten:
                                    if d5p != pred_val:
                                        d5p = d5p.clone()
                                        d5p.setPredecessor(pred_val)
                                elif self.shortening_mode == ShortenIfEqual:
                                    if d5.equals(pred_val):
                                        d5p = pred_val
                                self.propagate(d4, ret_site_c, d5p, c, False)

        if self.follow_returns_past_seeds and d1 == self.zero_value and (inc is None or inc.isEmpty()):
            callers = self.icfg.getCallersOf(method_that_needs_summary)

            for c in callers:
                for ret_site_c in self.icfg.getReturnSitesOfCallAt(c):
                    ret_function = self.flow_functions.getReturnFlowFunction(c, method_that_needs_summary, n,
                                                                             ret_site_c)
                    targets = self.compute_return_flow_function(ret_function, d1, d2, c,
                                                                 Collections.singleton(self.zero_value))
                    if targets is not None and not targets.isEmpty():
                        for d5 in targets:
                            if self.memory_manager is not None:
                                d5 = self.memory_manager.handleGeneratedMemoryObject(d2, d5)
                            if d5 is not None:
                                self.propagate(self.zero_value, ret_site_c, d5, c, True)

            if callers.isEmpty():
                ret_function = self.flow_functions.getReturnFlowFunction(None, method_that_needs_summary, n, None)
                ret_function.compute_targets( d2 )

    def compute_return_flow_function(self, ret_function, d1, d2, call_site, caller_side_ds):
        return ret_function.compute_targets( d2 )

    def process_normal_flow(self, edge):
        d1 = edge.factAtSource()
        n = edge.getTarget()
        d2 = edge.factAtTarget()

        for m in self.icfg.getSuccsOf(n):
            if self.kill_flag is not None:
                return
            flow_function = self.flow_functions.getNormalFlowFunction(n, m)
            res = self.compute_normal_flow_function(flow_function, d1, d2)
            if res is not None and not res.isEmpty():
                for d3 in res:
                    if self.memory_manager is not None and d2 != d3:
                        d3 = self.memory_manager.handleGeneratedMemoryObject(d2, d3)
                    if d3 is not None:
                        self.propagate(d1, m, d3, None, False)

    def compute_normal_flow_function(self, flow_function, d1, d2):
        return flow_function.compute_targets( d2 )

    def end_summary(self, m, d3):
        _map = self.end_summary.get(Pair(m, d3))
        return None if _map is None else _map.keySet()

    def add_end_summary(self, m, d1, e_p, d2):
        if d1 == self.zero_value:
            return True

        summaries = self.end_summary.putIfAbsentElseGet(Pair(m, d1), lambda: MyConcurrentHashMap()) # I don't know
        old_d2 = summaries.putIfAbsent(Pair(e_p, d2), d2)
        if old_d2 is not None:
            old_d2.addNeighbor(d2)
            return False
        return True

    def incoming(self, d1, m):
        _map = self.incoming.get(Pair(m, d1))
        return _map

    def add_incoming(self, m, d3, n, d1, d2):
        summaries = self.incoming.putIfAbsentElseGet(Pair(m, d3), lambda: MyConcurrentHashMap()) # I don't know
        _set = summaries.putIfAbsentElseGet(n, lambda: ConcurrentHashMap())  # I don't know
        return _set.put(d1, d2) is None

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
