import logging
import time

import PathDataErasureMode, pathBuilderFactory

from .infoflowconfiguration import InfoflowConfiguration
from .infoflowmanager import InfoflowManager
from .data.accesspathfactory import AccessPathFactory
from .util.systemclasshandler import SystemClassHandler
from .globaltaints.globaltaintmanager import GlobalTaintManager
from .problems.infoflowproblems import InfoflowProblem
from .problems.rules.propagationrulemanager import PropagationRuleManager
from .solver.ifdssolversingle import IFDSSolver
from .solver.memory.defaultmemorymanagerfactory import DefaultMemoryManagerFactory
from .data.pathbuilders.contextinsensitivepathbulder import ContextInsensitivePathBuilder as DefaultPathBuilder


logger = logging.getLogger(__file__)


class Infoflow:

    def __init__(self, config:InfoflowConfiguration):
        self.config = config
        self.results = None
        self.taint_wrapper = None
        self.hierarchy = None

        self.collected_sources = set()
        self.collected_sinks = set()
        self.manager = None
        self.dummy_main_method = None
        self.memory_manager_factory = DefaultMemoryManagerFactory()

    def create_memory_manager(self):
        if self.config.path_configuration.must_keep_statements():
            erasure_mode = PathDataErasureMode.EraseNothing
        elif pathBuilderFactory.supportsPathReconstruction():
            erasure_mode = PathDataErasureMode.EraseNothing
        elif pathBuilderFactory.isContextSensitive():
            erasure_mode = PathDataErasureMode.KeepOnlyContextData
        else:
            erasure_mode = PathDataErasureMode.EraseAll
        memory_manager = self.memory_manager_factory.get_memory_manager(False, erasure_mode)
        return memory_manager

    def create_forward_solver(self, forward_problem:InfoflowProblem)->IFDSSolver:
        solver_config = self.config.solver_configuration
        forward_solver = IFDSSolver(forward_problem, solver_config)

        forward_solver.solver_id = True
        forward_solver.max_join_point_abstractions = solver_config.max_join_point_abstractions
        forward_solver.max_callees_per_call_site = solver_config.max_callees_per_call_site
        forward_solver.max_abstraction_path_length = solver_config.max_abstraction_path_length

        return forward_solver

    def initialize_infoflow_manager(self, sources_sinks, i_cfg, global_taint_manager):
        return InfoflowManager(self.config, None, i_cfg, sources_sinks, self.taint_wrapper, self.hierarchy,
                               AccessPathFactory(self.config), global_taint_manager)

    def run_taint_analysis(self, sources_sinks, additional_seeds, i_cfg, performance_data=None):

        has_more_sources = sources_sinks[1:]

        while has_more_sources:

            memory_manager = self.create_memory_manager()

            solvers = dict()
            global_taint_manager = GlobalTaintManager(solvers)

            self.manager = self.initialize_infoflow_manager(sources_sinks, i_cfg, global_taint_manager)

            zero_value = None
            """
            backward_solver = None  # FlowSensitive case of createAliasAnalysis

            if backward_solver is not None:
                zero_value = backward_solver.get_tabulation_problem().create_zero_value()
                solvers['backward'] = backward_solver
            """

            forward_problem = InfoflowProblem(self.manager, zero_value, PropagationRuleManager(self.manager, zero_value,
                                                                                               self.results))

            forward_solver = self.create_forward_solver(forward_problem)

            self.manager.forward_solver(forward_solver)
            solvers['forward'] = forward_solver

            forward_solver.memory_manager = memory_manager

            #forward_problem.taint_propagation_handler = taint_propagation_handler
            #forward_problem.taint_wrapper = taint_wrapper

            #if native_call_handler is not None:
            #    forward_problem.set_native_call_handler(native_call_handler)

            result_executor = None
            before_path_reconstruction = 0
            sink_count = 0

            for sm in self.get_methods_for_seeds(i_cfg):
                sink_count += self.scan_method_for_sources_sinks(sources_sinks, forward_problem, sm)

            if additional_seeds is not None:
                for meth in additional_seeds:
                    m = Scene.v().getMethod(meth)
                    if not m.hasActiveBody():
                        logger.warn("Seed method { has no active body", m)
                        continue

                    forward_problem.addInitialSeeds(m.getActiveBody().getUnits().getFirst(),
                                                    [forward_problem.zeroValue()])

            if not forward_problem.hasInitialSeeds():
                logger.error("No sources found, aborting analysis")
                continue

            if sink_count == 0:
                logger.error("No sinks found, aborting analysis")
                continue

            logger.info("Source lookup done, found { sources and { sinks.",
                        forward_problem.getInitialSeeds().size(), sink_count)

            #if taint_wrapper is not None:
                taint_wrapper.initialize(self.manager)

            if native_call_handler is not None:
                native_call_handler.initialize(self.manager)

            propagation_results = forward_problem.getResults()

            builder = DefaultPathBuilder()

            forward_solver.solve()

            if taint_wrapper is not None:
                logger.info("Taint_wrapper hits: " + taint_wrapper.getWrapperHits())
                logger.info("Taint_wrapper misses: " + taint_wrapper.getWrapperMisses())

            res = propagation_results.get_results()

            if self.config.getIncrementalResultReporting():
                builder.run_incremental_path_compuation()
            else:
                builder.compute_taint_paths( res )
                res = None

                self.results.add_all(builder.results())

            has_more_sources = has_more_sources[1:]

        for handler in self.postProcessors:
            self.results = handler.onResultsAvailable(self.results, i_cfg)

        if self.results is None or len(self.results) <= 0:
            logger.warn("No results found.")
        elif logger.is_info_enabled():
            for sink in self.results.get_results().keySet():
                logger.info("The sink { in method { was called with values from the following sources:", sink,
                            i_cfg.get_method_of( sink.getStmt() ).get_signature() )
                for source in self.results.get_results().get( sink ):
                    logger.info("- { in method {", source, i_cfg.get_method_of( source.getStmt() ).get_signature() )
                    if source.get_path() is not None:
                        logger.info("\ton Path: ")
                        for p in source.get_path():
                            logger.info("\t -> " + i_cfg.get_method_of( p ) )
                            logger.info("\t\t -> " + p)

    def get_methods_for_seeds(self, icfg):
        seeds = list()
        if Scene.v().hasCallGraph():
            reachable_methods = Scene.v().getReachableMethods()
            reachable_methods.update()
            for method in reachable_methods:
                sm = method
                if self.is_valid_seed_method(sm):
                    seeds.append(sm)
        else:
            before_seed_methods = time.time_ns()
            done_set = set()
            for sm in Scene.v().getEntryPoints():
                self.get_methods_for_seeds_incremental(sm, done_set, seeds, icfg)
            logger.info("Collecting seed methods took { seconds", (time.time_ns() - before_seed_methods) / 1E9)

        return seeds

    def get_methods_for_seeds_incremental(self, sm, done_set, seeds, icfg):
        assert Scene.v().hasFastHierarchy()
        if not sm.isConcrete() or not sm.getDeclaringClass().isApplicationClass() or not done_set.add(sm):
            return
        seeds.append(sm)
        for u in sm.retrieveActiveBody().getUnits():
            stmt = u
            if stmt.containsInvokeExpr():
                for callee in icfg.get_callees_of_call_at( stmt ):
                    if self.is_valid_seed_method(callee):
                        self.get_methods_for_seeds_incremental(callee, done_set, seeds, icfg)

    def scan_method_for_sources_sinks(self, sources_sinks, forward_problem, m):
        if self.collected_sources is None:
            self.collected_sources = set()
            self.collected_sinks = set()

        sink_count = 0
        if m.hasActiveBody():
            if not self.is_valid_seed_method(m):
                return sink_count

            units = m.getActiveBody().getUnits()
            for u in units:
                s = u
                if sources_sinks.get_source_info( s, self.manager ) is not None:
                    forward_problem.add_initial_seeds(u, forward_problem.zeroValue())
                    if self.config.getLogSourcesAndSinks():
                        self.collected_sources.add(s)
                    logger.debug("Source found: { in {", u, m.get_signature() )
                
                if sources_sinks.get_sink_info( s, self.manager, None ) is not None:
                    sink_count += 1
                    if self.config.getLogSourcesAndSinks():
                        self.collected_sinks.add(s)
                    logger.debug("Sink found: { in {", u, m.get_signature() )
                
        return sink_count

    def is_valid_seed_method(self, sm):
        if sm == self.dummy_main_method:
            return False
        if self.dummy_main_method is not None and sm.getDeclaringClass() == self.dummy_main_method.getDeclaringClass():
            return False

        class_name = sm.getDeclaringClass().getName()
        if self.config.getIgnoreFlowsInSystemPackages() and SystemClassHandler().is_class_in_system_package(class_name)\
                and not self.is_user_code_class(class_name):
            return False

        if self.config.getExcludeSootLibraryClasses() and sm.getDeclaringClass().isLibraryClass():
            return False

        return True

    def is_user_code_class(self, class_name):
        return False
