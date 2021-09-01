import PathDataErasureMode, pathBuilderFactory

from .ifds.globaltaintmanager import GlobalTaintManager
from .ifds.infoflowproblems import InfoflowProblem
from .ifds.propagationrulemanager import PropagationRuleManager
from .ifds.ifdssolversingle import IFDSSolver

import logging

logger = logging.getLogger(__file__)


class Infoflow:

    def __init__(self, config):
        self.config = config

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
        return InfoflowManager(self.config, None, i_cfg, sources_sinks, taintWrapper, hierarchy,
                               AccessPathFactory(self.config), global_taint_manager)

    def run_taint_analysis(self, sources_sinks, additional_seeds, i_cfg, performance_data):
        has_more_sources = sources_sinks[1:]

        while has_more_sources:

            memory_manager = self.create_memory_manager()

            solvers = dict()
            global_taint_manager = GlobalTaintManager(solvers)

            manager = self.initialize_infoflow_manager(sources_sinks, i_cfg, global_taint_manager)

            zero_value = None
            aliasing_strategy = self.createAliasAnalysis(sources_sinks, i_cfg, memory_manager)
            backward_solver = aliasing_strategy.getSolver()

            if backward_solver is not None:
                zero_value = backward_solver.getTabulationProblem().createZeroValue()
                solvers['backward'] = backward_solver

            aliasing = createAliasController(aliasing_strategy)
            if dummyMainMethod is not None:
                aliasing.excludeMethodFromMustAlias(dummyMainMethod)
            manager.setAliasing(aliasing)

            forward_problem = InfoflowProblem(manager, zero_value, PropagationRuleManager())

            forward_solver = self.create_forward_solver(forward_problem)

            manager.setForwardSolver(forward_solver)
            if aliasing_strategy.getSolver() is not None:
                aliasing_strategy.getSolver().getTabulationProblem().getManager().setForwardSolver(forward_solver)
            solvers['forward'] = forward_solver

            memoryWatcher.addSolver(forward_solver)

            forward_solver.set_memory_manager(memory_manager)

            forward_problem.setTaintPropagationHandler(taintPropagationHandler)
            forward_problem.setTaintWrapper(taintWrapper)
            if nativeCallHandler is not None:
                forward_problem.setNativeCallHandler(nativeCallHandler)

            if aliasing_strategy.getSolver() is not None:
                aliasing_strategy.getSolver().getTabulationProblem().setActivationUnitsToCallSites(forward_problem)

            timeout_watcher = None
            path_timeout_watcher = None
            if self.config.getDataFlowTimeout() > 0:
                timeout_watcher = FlowDroidTimeoutWatcher(self.config.getDataFlowTimeout(), results)
                timeout_watcher.addSolver(forward_solver)
                if aliasing_strategy.getSolver() is not None:
                    timeout_watcher.addSolver(aliasing_strategy.getSolver())
                timeout_watcher.start()


            resultExecutor = None
            before_path_reconstruction = 0
            try:
                if self.config.getFlowSensitiveAliasing() and not aliasing_strategy.isFlowSensitive():
                    logger.warn("Trying to use a flow-sensitive aliasing with an "
                            + "aliasing strategy that does not support this feature")
                if self.config.getFlowSensitiveAliasing() and self.config.getSolverself.configuration().getMaxJoinPointAbstractions() > 0:
                    logger.warn("Running with limited join poabstractions can break context-"
                            + "sensitive path builders")
                sink_count = 0

                for sm in getMethodsForSeeds(i_cfg):
                    sink_count += scanMethodForSourcesSinks(sources_sinks, forward_problem, sm)

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

                performance_data.setSourceCount(forward_problem.getInitialSeeds().size())
                performance_data.setSinkCount(sink_count)

                if taintWrapper is not None:
                    taintWrapper.initialize(manager)
                if nativeCallHandler is not None:
                    nativeCallHandler.initialize(manager)

                propagation_results = forward_problem.getResults()
                resultExecutor = executorFactory.createExecutor(numThreads, False, self.config)
                """
                resultExecutor.setThreadFactory(ThreadFactory():
    
                    @Override
                    public Thread newThread(Runnable r):
                        Thread thrPath = Thread(r)
                        thrPath.setDaemon(True)
                        thrPath.setName("FlowDroid Path Reconstruction")
                        return thrPath
                    
               )
                """

                builder = createPathBuilder(resultExecutor)

                if self.config.getIncrementalResultReporting():
                    initializeIncrementalResultReporting(propagation_results, builder)

                if performance_data.getTaintPropagationSeconds() < 0:
                    performance_data.setTaintPropagationSeconds(0)
                before_taint_propagation = System.nanoTime()

                onBeforeTaintPropagation(forward_solver, backward_solver)
                forward_solver.solve()

                terminate_tries = 0
                while terminate_tries < 10:
                    if executor.getActiveCount() != 0 or !executor.isTerminated():
                        terminate_tries += 1
                        try:
                            Thread.sleep(500)
                        except InterruptedError as e:
                            logger.error("Could not wait for executor termination", e)

                    else:
                        break

                if executor.getActiveCount() != 0 or !executor.isTerminated():
                    logger.error("Executor did not terminate gracefully")
                if executor.getException() is not None:
                    raise RuntimeError("An exception has occurred in an executor", executor.getException())

                performance_data.updateMaxMemoryConsumption(getUsedMemory())
                taint_propagation_seconds = Math.round((System.nanoTime() - before_taint_propagation) / 1E9)
                performance_data.addTaintPropagationSeconds(taint_propagation_seconds)

                if taintWrapper is not None:
                    logger.info("Tawrapper hits: " + taintWrapper.getWrapperHits())
                    logger.info("Tawrapper misses: " + taintWrapper.getWrapperMisses())


                onTaintPropagationCompleted(forward_solver, backward_solver)

                res = propagation_results.getResults()
                propagation_results = None

                removeEntailedAbstractions(res)

                if nativeCallHandler is not None:
                    nativeCallHandler.shutdown()

                logger.info(
                        "IFDS problem with { forward and { backward edges solved in { seconds, processing { results...",
                        forward_solver.propagation_count(),
                        0 if aliasing_strategy.getSolver() is None else aliasing_strategy.getSolver().getPropagationCount(),
                        taint_propagation_seconds, 0 if res is None else res.size())

                reason = forward_solver.get_termination_reason()
                if reason is not None:
                    if isinstance(reason, OutOfMemoryReason):
                        results.setTerminationState(
                                results.getTerminationState() | InfoflowResults.TERMINATION_DATA_FLOW_OOM)
                    elif isinstance(reason, TimeoutReason):
                        results.setTerminationState(
                                results.getTerminationState() | InfoflowResults.TERMINATION_DATA_FLOW_TIMEOUT)

                performance_data.updateMaxMemoryConsumption(getUsedMemory())
                logger.info(String.format("Current memory consumption: %d MB", getUsedMemory()))

                if timeout_watcher is not None:
                    timeout_watcher.stop()
                memoryWatcher.removeSolver(forward_solver)
                forward_solver.cleanup()
                forward_solver = None
                forward_problem = None

                solver_peer_group = None

                aliasing = None
                if aliasing_strategy.getSolver() is not None:
                    aliasing_strategy.getSolver().terminate()
                    memoryWatcher.removeSolver(aliasing_strategy.getSolver())

                aliasing_strategy.cleanup()
                aliasing_strategy = None

                if self.config.getIncrementalResultReporting():
                    res = None
                i_cfg.purge()

                if manager is not None:
                    manager.cleanup()
                manager = None

                Runtime.getRuntime().gc()
                performance_data.updateMaxMemoryConsumption(getUsedMemory())
                logger.info(String.format("Memory consumption after cleanup: %d MB", getUsedMemory()))

                if self.config.getPathself.configuration().getPathReconstructionTimeout() > 0:
                    path_timeout_watcher = FlowDroidTimeoutWatcher(
                            self.config.getPathself.configuration().getPathReconstructionTimeout(), results)
                    path_timeout_watcher.addSolver(builder)
                    path_timeout_watcher.start()

                before_path_reconstruction = System.nanoTime()

                if self.config.getIncrementalResultReporting():
                    builder.runIncrementalPathCompuation()

                    try:
                        resultExecutor.awaitCompletion()
                    except InterruptedError as e:
                        logger.error("Could not wait for executor termination", e)

                else:
                    memoryWatcher.addSolver(builder)
                    builder.computeTaintPaths(res)
                    res = None

                    ISolverTerminationReason reason = builder.getTerminationReason()
                    if reason is not None:
                        if isinstance(reason, OutOfMemoryReason):
                            results.setTerminationState(results.getTerminationState()
                                    | InfoflowResults.TERMINATION_PATH_RECONSTRUCTION_OOM)
                        elif isinstance(reason, TimeoutReason):
                            results.setTerminationState(results.getTerminationState()
                                    | InfoflowResults.TERMINATION_PATH_RECONSTRUCTION_TIMEOUT)

                    try:
                        pathTimeout = self.config.getPathself.configuration().getPathReconstructionTimeout()
                        if pathTimeout > 0:
                            resultExecutor.awaitCompletion(pathTimeout + 20, TimeUnit.SECONDS)
                        else:
                            resultExecutor.awaitCompletion()
                    except InterruptedError as e:
                        logger.error("Could not wait for executor termination", e)

                    self.results.addAll(builder.getResults())

                resultExecutor.shutdown()

                if builder.isKilled():
                    logger.warn("Path reconstruction aborted. The reported results may be incomplete. "
                            + "You might want to try again with sequential path processing enabled.")
            finally:
                if resultExecutor is not None:
                    resultExecutor.shutdown()

                if timeout_watcher is not None:
                    timeout_watcher.stop()
                if path_timeout_watcher is not None:
                    path_timeout_watcher.stop()

                if aliasing_strategy is not None:
                    solver = aliasing_strategy.getSolver()
                    if solver is not None:
                        solver.terminate()

                has_more_sources = has_more_sources[1:]

                memoryWatcher.close()

                forward_problem = None
                forward_solver = None
                if manager is not None:
                    manager.cleanup()
                manager = None


            Runtime.getRuntime().gc()
            performance_data.updateMaxMemoryConsumption(getUsedMemory())
            performance_data.setPathReconstructionSeconds(
                    Math.round((System.nanoTime() - before_path_reconstruction) / 1E9))

            logger.info(String.format("Memory consumption after path building: %d MB", getUsedMemory()))
            logger.info(String.format("Path reconstruction took %d seconds",
                                       performance_data.getPathReconstructionSeconds()))

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
