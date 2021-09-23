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

l = logging.getLogger(name=__name__)


class IFDSSolver:

    def __init__(self, tabulation_problem, flow_function_cache_builder: CacheBuilder):

#        self.DEFAULT_CACHE_BUILDER = CacheBuilder.newBuilder().concurrencyLevel(
#            multiprocessing.cpu_count()).initialCapacity(10000).softValues()
        self.executor = None
        self.num_threads = None
        self.jump_functions = list()
        self.icfg = None
        self.end_summary = list()
        self.incoming = list()
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
        if l.is_debug_enabled():
            self.flow_function_cache_builder = flow_function_cache_builder.recordStats()
            self.zero_value = tabulation_problem.zero_value()
            self.icfg = tabulation_problem.interprocedural_cfg()
            self.flow_functions = ZeroedFlowFunctions(tabulation_problem.flow_functions(), self.zero_value)\
                if tabulation_problem.auto_add_zero() else tabulation_problem.flow_functions()
        if self.flow_function_cache_builder is not None:
            self.ff_cache = FlowFunctionCache(self.flow_functions, flow_function_cache_builder)
            self.flow_functions = self.ff_cache
        else:
            self.ff_cache = None
            self.flow_functions = self.flow_functions
            self.initial_seeds = tabulation_problem.initial_seeds()
            self.follow_returns_past_seeds = tabulation_problem.follow_returns_past_seeds()
            self.num_threads = max(1, tabulation_problem.num_threads())
            self.executor = self.get_executor()

    def set_solver_id(self, solver_id: bool):
        self.solver_id = solver_id

    def solve(self):
        self.reset()

        for listener in self.notification_listeners:
            listener.notifySolverStarted(self)

        self.submit_initial_seeds()
        self.await_completion_compute_values_and_shutdown()

        for listener in self.notification_listeners:
            listener.notifySolverTerminated(self)

    def submit_initial_seeds(self):
        for seed in self.initial_seeds.entrySet():
            start_point = seed.getKey()
            for val in seed.getValue():
                self.propagate(self.zero_value, start_point, val, None, False)
            self.add_function(PathEdge(self.zero_value, start_point, self.zero_value))

    def await_completion_compute_values_and_shutdown(self):
        self.run_executor_and_await_completion()
        if l.is_debug_enabled():
            self.print_stats()

        self.executor.shutdown()

        while not self.executor.is_terminated():
            try:
                Thread.sleep(100)
            except InterruptedError as e:
                pass

    def run_executor_and_await_completion(self):
        try:
            self.executor.awaitCompletion()
        except InterruptedError as e:
            print(e)

        exception = self.executor.getException()
        if exception is not None:
            raise RuntimeError("There were exceptions during IFDS analysis. Exiting.", exception)

    def schedule_edge_processing(self, edge):
        if self.kill_flag is not None or self.executor.isTerminating() or self.executor.is_terminated():
            return

        self.executor.execute(PathEdgeProcessingTask(edge, self.solver_id))
        self.propagation_count += 1

    def process_call(self, edge):
        d1 = edge.factAtSource()
        n = edge.getTarget()
        d2 = edge.factAtTarget()
        assert d2 is not None

        return_site_ns = self.icfg.get_return_sites_of_call_at(n)
        callees = self.icfg.get_callees_of_call_at(n)

        if callees is not None and not callees.is_empty():
            if self.max_callees_per_call_site < 0 or callees.size() <= self.max_callees_per_call_site:
                for callee in callees.stream().filter(lambda m: m.isConcrete()):
                    s_called_proc_n = None # Have to fix
                    if self.kill_flag is not None:
                        return

                    function = self.flow_functions.getCallFlowFunction(n, s_called_proc_n)
                    res = self.compute_call_flow_function(function, d1, d2)

                    if res is not None and not res.is_empty():
                        start_points_of = self.icfg.get_start_points_of(s_called_proc_n)
                        for d3 in res:
                            if self.memory_manager is not None:
                                d3 = self.memory_manager.handle_generated_memory_object(d2, d3)
                            if d3 is None:
                                continue

                            for sP in start_points_of:
                                self.propagate(d3, sP, d3, n, False)

                            if not self.add_incoming(s_called_proc_n, d3, n, d1, d2):
                                continue

                            self.apply_end_summary_on_call(d1, n, d2, return_site_ns, s_called_proc_n, d3)

        for return_site_n in return_site_ns:
            call_to_return_flow_function = self.flow_functions.getCallToReturnFlowFunction(n, return_site_n)
            res = self.compute_call_to_return_flow_function(call_to_return_flow_function, d1, d2)

            if res is not None and not res.is_empty():
                for d3 in res:
                    if self.memory_manager is not None:
                        d3 = self.memory_manager.handle_generated_memory_object(d2, d3)
                    if d3 is not None:
                        self.propagate(d1, return_site_n, d3, n, False)

    def on_end_summary_applied(self, n, s_called_proc, d3):
        pass

    def apply_end_summary_on_call(self, d1, n, d2, return_site_ns, s_called_proc_n, d3):
        end_summ = self.end_summary(s_called_proc_n, d3)

        if end_summ is not None and not end_summ.is_empty():
            for entry in end_summ:
                eP = entry.getO1()
                d4 = entry.getO2()

                for ret_site_n in return_site_ns:
                    ret_function = self.flow_functions.get_return_flow_function(n, s_called_proc_n, eP, ret_site_n)
                    ret_flow_res = self.compute_return_flow_function(ret_function, d3, d4, n, set(d1))

                    if ret_flow_res is not None and not ret_flow_res.is_empty():
                        for d5 in ret_flow_res:
                            if self.memory_manager is not None:
                                d5 = self.memory_manager.handle_generated_memory_object(d4, d5)

                            d5p = d5
                            if self.shortening_mode == PredecessorShorteningMode['AlwaysShorten']:
                                if d5p != d2:
                                    d5p = d5p.clone()
                                    d5p.setPredecessor(d2)
                            elif self.shortening_mode == PredecessorShorteningMode['ShortenIfEqual']:
                                if d5 == d2:
                                    d5p = d2

                            self.propagate(d1, ret_site_n, d5p, n, False)
            self.on_end_summary_applied(n, s_called_proc_n, d3)

    def compute_call_flow_function(self, call_flow_function, d1, d2):
        return call_flow_function.compute_targets(d2)

    def compute_call_to_return_flow_function(self, call_to_return_flow_function, d1, d2):
        return call_to_return_flow_function.compute_targets(d2)

    def process_exit(self, edge):
        n = edge.getTarget()
        method_that_needs_summary = self.icfg.get_method_of(n)

        d1 = edge.factAtSource()
        d2 = edge.factAtTarget()

        if not self.add_end_summary(method_that_needs_summary, d1, n, d2):
            return

        inc = self.incoming(d1, method_that_needs_summary)

        if inc is not None and not inc.is_empty():
            for entry in inc.entrySet():
                if self.kill_flag is not None:
                    return

                c = entry.getKey()
                caller_side_ds = entry.getValue().keys()
                for ret_site_c in self.icfg.get_return_sites_of_call_at(c):
                    ret_function = self.flow_functions.get_return_flow_function(c, method_that_needs_summary, n, ret_site_c)
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

                                if self.shortening_mode == PredecessorShorteningMode['AlwaysShorten']:
                                    if d5p != pred_val:
                                        d5p = d5p.clone()
                                        d5p.setPredecessor(pred_val)
                                elif self.shortening_mode == PredecessorShorteningMode['ShortenIfEqual']:
                                    if d5 == pred_val:
                                        d5p = pred_val
                                self.propagate(d4, ret_site_c, d5p, c, False)

        if self.follow_returns_past_seeds and d1 == self.zero_value and (inc is None or inc.is_empty()):
            callers = self.icfg.get_callers_of(method_that_needs_summary)

            for c in callers:
                for ret_site_c in self.icfg.get_return_sites_of_call_at(c):
                    ret_function = self.flow_functions.get_return_flow_function(c, method_that_needs_summary, n,
                                                                                ret_site_c)
                    targets = self.compute_return_flow_function(ret_function, d1, d2, c,
                                                                 set(self.zero_value))
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
        d1 = edge.factAtSource()
        n = edge.getTarget()
        d2 = edge.factAtTarget()

        for m in self.icfg.get_succs_of(n):
            if self.kill_flag is not None:
                return
            flow_function = self.flow_functions.getNormalFlowFunction(n, m)
            res = self.compute_normal_flow_function(flow_function, d1, d2)
            if res is not None and not res.is_empty():
                for d3 in res:
                    if self.memory_manager is not None and d2 != d3:
                        d3 = self.memory_manager.handle_generated_memory_object(d2, d3)
                    if d3 is not None:
                        self.propagate(d1, m, d3, None, False)

    def compute_normal_flow_function(self, flow_function, d1, d2):
        return flow_function.compute_targets(d2)

    def propagate(self, source_val, target, target_val, related_call_site, is_unbalanced_return):
        if self.memory_manager is not None:
            source_val = self.memory_manager.handle_memory_object(source_val)
            target_val = self.memory_manager.handle_memory_object(target_val)
            if target_val is None:
                return

        if self.max_abstraction_path_length >= 0 and target_val.getPathLength() > self.max_abstraction_path_length:
            return

        edge = PathEdge(source_val, target, target_val)
        existing_val = self.add_function(edge)
        if existing_val is not None:
            if existing_val != target_val:
                if self.memory_manager is None:
                    is_essential = related_call_site is not None and self.icfg.is_call_stmt(related_call_site)
                else:
                    is_essential = self.memory_manager.is_essential_join_point(target_val, related_call_site)

                if self.max_join_point_abstractions < 0 \
                    or existing_val.get_neighbor_count() < self.max_join_point_abstractions \
                    or is_essential:
                    existing_val.add_neighbor(target_val)
        else:
            active_val = target_val.getActiveCopy()
            if active_val != target_val:
                active_edge = PathEdge(source_val, target, active_val)
                if self.jump_functions.containsKey(active_edge):
                    return
            self.schedule_edge_processing(edge)

    def add_function(self, edge):
        return self.jump_functions.putIfAbsent(edge, edge.factAtTarget())

    def end_summary(self, m, d3):
        map = self.end_summary.get(Pair(m, d3))
        return None if map is None else map.keys()

    def add_end_summary(self, m, d1, e_p, d2):
        if d1 == self.zero_value:
            return True

        summaries = self.end_summary.putIfAbsentElseGet(Pair(m, d1), lambda: MyConcurrentHashMap()) # I don't know
        old_d2 = summaries.putIfAbsent(Pair(e_p, d2), d2)
        if old_d2 is not None:
            old_d2.add_neighbor(d2)
            return False
        return True

    def incoming(self, d1, m):
        map = self.incoming.get(Pair(m, d1))
        return map

    def add_incoming(self, m, d3, n, d1, d2):
        summaries = self.incoming.putIfAbsentElseGet(Pair(m, d3), lambda: MyConcurrentHashMap()) # I don't know
        set = summaries.putIfAbsentElseGet(n, lambda: ConcurrentHashMap())  # I don't know
        return set.put(d1, d2) is None

    def get_executor(self):
        executor = SetPoolExecutor(1, self.num_threads, 30, TimeUnit.SECONDS, LinkedBlockingQueue())
        executor.setThreadFactory(ThreadFactory())
        """{

            @Override
            Thread newThread(Runnable r) {
                Thread thrIFDS = new Thread(r)
                thrIFDS.setDaemon(true)
                thrIFDS.setName("IFDS Solver")
                return thrIFDS
            }
        }"""

        return executor

    def get_debug_name(self):
        return "FAST IFDS SOLVER"

    def print_stats(self):
        if l.is_debug_enabled():
            if self.ff_cache is not None:
                self.ff_cache.print_stats()
        else:
            l.info("No statistics were collected, as DEBUG is disabled.")

    class PathEdgeProcessingTask:

        def __init__(self):
            self.edge
            self.solver_id

        def path_edge_processing_task(self, edge, solver_id):
            self.edge = edge
            self.solver_id = solver_id

        def run(self):
            target = self.edge.getTarget()
            if self.icfg.is_call_stmt(target):
                self.processCall(self.edge)
            else:
                if self.icfg.is_exit_stmt(target):
                    self.processExit(self.edge)
                if not self.icfg.get_succs_of(target).is_empty():
                    self.processNormalFlow(self.edge)

        def hash_code(self):
            prime = 31
            result = 1
            result = prime * result + (0 if self.edge is None else self.edge.hash_code())
            result = prime * result + (1231 if self.solver_id else 1237)
            return result

        def getClass(self):
            pass

        def __eq__(self, other):
            if self == other:
                return True
            if other is None:
                return False
            if self.edge is None:
                if other.edge is not None:
                    return False
            elif not self.edge == other.edge:
                return False
            if self.solver_id != other.solver_id:
                return False
            return True

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
