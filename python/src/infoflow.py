import logging
import PathDataErasureMode, pathBuilderFactory

from .infoflow.globaltaints.globaltaintmanager import GlobalTaintManager
from .infoflow.problems.infoflowproblems import InfoflowProblem
from .infoflow.problems.rules.propagationrulemanager import PropagationRuleManager
from .infoflow.solver.ifdssolversingle import IFDSSolver

logger = logging.getLogger(__file__)


class Infoflow:

    def __init__(self, config):
        self.config = config
        self.results = None

        self.collected_sources = set()
        self.collected_sinks = set()
        self.manager = None
        self.dummy_main_method = None

    def create_memory_manager(self):
        if self.config.getPathConfiguration().mustKeepStatements():
            erasure_mode = PathDataErasureMode.EraseNothing
        elif pathBuilderFactory.supportsPathReconstruction():
            erasure_mode = PathDataErasureMode.EraseNothing
        elif pathBuilderFactory.isContextSensitive():
            erasure_mode = PathDataErasureMode.KeepOnlyContextData
        else:
            erasure_mode = PathDataErasureMode.EraseAll
        memory_manager = memoryManagerFactory.getMemoryManager( False, erasure_mode )
        return memory_manager

    def create_forward_solver(self, forward_problem):
        solver_config = self.config.getSolverself.configuration()
        forward_solver = IFDSSolver(forward_problem, solver_config)

        forward_solver.solver_id = True
        forward_solver.max_join_point_abstractions = solver_config.getMaxJoinPointAbstractions()
        forward_solver.max_callees_per_call_site = solver_config.getMaxCalleesPerCallSite()
        forward_solver.max_abstraction_path_length = solver_config.getMaxAbstractionPathLength()

        return forward_solver

    def initialize_infoflow_manager(self, sources_sinks, i_cfg, global_taint_manager):
        return InfoflowManager(self.config, None, i_cfg, sources_sinks, taint_wrapper, hierarchy,
                               AccessPathFactory(self.config), global_taint_manager)

    def run_taint_analysis(self, sources_sinks, additional_seeds, i_cfg, performance_data):
        has_more_sources = sources_sinks[1:]

        while has_more_sources:

            memory_manager = self.create_memory_manager()

            solvers = dict()
            global_taint_manager = GlobalTaintManager(solvers)

            self.manager = self.initialize_infoflow_manager(sources_sinks, i_cfg, global_taint_manager)

            zero_value = None
            backward_solver = None  # FlowSensitive case of createAliasAnalysis

            if backward_solver is not None:
                zero_value = backward_solver.get_tabulation_problem().create_zero_value()
                solvers['backward'] = backward_solver

            forward_problem = InfoflowProblem(self.manager, zero_value, PropagationRuleManager(self.manager, zero_value,
                                                                                          self.results))

            forward_solver = self.create_forward_solver(forward_problem)

            self.manager.forward_solver(forward_solver)
            solvers['forward'] = forward_solver

            forward_solver.set_memory_manager(memory_manager)

            forward_problem.taint_propagation_handler = taint_propagation_handler
            forward_problem.taint_wrapper = taint_wrapper

            if native_call_handler is not None:
                forward_problem.set_native_call_handler(native_call_handler)

            result_executor = None
            before_path_reconstruction = 0
            sink_count = 0

            for sm in getMethodsForSeeds(i_cfg):
                sink_count += scan_method_for_sources_sinks(sources_sinks, forward_problem, sm)

            if additional_seeds is not None:
                for meth in additional_seeds:
                    m = Scene.v().getMethod(meth)
                    if not m.hasActiveBody():
                        logger.warn("Seed method { has no active body", m)
                        continue

                    forward_problem.addInitialSeeds(m.getActiveBody().getUnits().getFirst(),
                            Collections.singleton(forward_problem.zeroValue()))

            if not forward_problem.hasInitialSeeds():
                logger.error("No sources found, aborting analysis")
                continue

            if sink_count == 0:
                logger.error("No sinks found, aborting analysis")
                continue

            logger.info("Source lookup done, found { sources and { sinks.",
                    forward_problem.getInitialSeeds().size(), sink_count)

            if taint_wrapper is not None:
                taint_wrapper.initialize(self.manager)

            if native_call_handler is not None:
                native_call_handler.initialize(self.manager)

            propagation_results = forward_problem.getResults()

            builder = createPathBuilder()

            forward_solver.solve()

            if taint_wrapper is not None:
                logger.info("Taint_wrapper hits: " + taint_wrapper.getWrapperHits())
                logger.info("Taint_wrapper misses: " + taint_wrapper.getWrapperMisses())

            res = propagation_results.getResults()

            if self.config.getIncrementalResultReporting():
                builder.runIncrementalPathCompuation()
                result_executor.awaitCompletion()
            else:
                builder.computeTaintPaths(res)
                res = None

                result_executor.awaitCompletion()

                self.results.addAll(builder.getResults())

            has_more_sources = has_more_sources[1:]

        for handler in self.postProcessors:
            results = handler.onResultsAvailable(results, i_cfg)

        if results is None or results.isEmpty():
            logger.warn("No results found.")
        elif logger.is_info_enabled():
            for sink in results.getResults().keySet():
                logger.info("The sink { in method { was called with values from the following sources:", sink,
                            i_cfg.getMethodOf(sink.getStmt()).getSignature())
                for source in results.getResults().get(sink):
                    logger.info("- { in method {", source, i_cfg.getMethodOf(source.getStmt()).getSignature())
                    if source.getPath() is not None:
                        logger.info("\ton Path: ")
                        for p in source.getPath():
                            logger.info("\t -> " + i_cfg.getMethodOf(p))
                            logger.info("\t\t -> " + p)

    def scan_method_for_sources_sinks(self, sourcesSinks, forwardProblem, m):
        if self.collected_sources is None:
            self.collected_sources = set()
            self.collected_sinks = set()

        sink_count = 0
        if m.hasActiveBody():
            if not self.is_valid_seed_method( m ):
                return sink_count

            units = m.getActiveBody().getUnits()
            for u in units:
                s = u
                if sourcesSinks.getSourceInfo(s, self.manager) is not None:
                    forwardProblem.addInitialSeeds(u, Collections.singleton(forwardProblem.zeroValue()))
                    if getConfig().getLogSourcesAndSinks():
                        collectedSources.add(s)
                    logger.debug("Source found: { in {", u, m.getSignature())
                
                if sourcesSinks.getSinkInfo(s, self.manager, None) is not None:
                    sink_count += 1
                    if getConfig().getLogSourcesAndSinks():
                        collectedSinks.add(s)
                    logger.debug("Sink found: { in {", u, m.getSignature())
                
        return sink_count

    def is_valid_seed_method(self, sm):
        if sm == self.dummy_main_method:
            return False
        if self.dummy_main_method is not None and sm.getDeclaringClass() == self.dummy_main_method.getDeclaringClass():
            return False

        class_name = sm.getDeclaringClass().getName()
        if self.config.getIgnoreFlowsInSystemPackages() and SystemClassHandler.v().is_class_in_system_package( class_name ) \
                and not self.is_user_code_class(class_name):
            return False

        if self.config.getExcludeSootLibraryClasses() and sm.getDeclaringClass().isLibraryClass():
            return False

        return True

    def is_user_code_class(self, class_name):
        return False
