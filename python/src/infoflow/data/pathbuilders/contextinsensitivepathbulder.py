import logging

logger = logging.getLogger(__file__)


class ContextInsensitivePathBuilder:

    def __init__(self):
        self.path_cache = list()
        self.results = InfoflowResults()
        self.notification_listeners = set()
        self.kill_flag = None

    def compute_taint_paths(self, res):
        if res is None or res.isEmpty():
            return

        logger.info( "Obtainted {} connections between sources and sinks", res.size() )

        cur_res_idx = 0
        for abs in res:
            if self.kill_flag is not None:
                res.clear()
                break

            cur_res_idx += 1
            logger.info("Building path %d..." % cur_res_idx)
            task = self.getTaintPathTask( abs )
            if task is not None:
                executor.execute( task )

            if self.triggerComputationForNeighbors() and abs.getAbstraction().getNeighbors() is not None:
                for neighbor in abs.getAbstraction().getNeighbors():
                    neighbor_at_sink = AbstractionAtSink( abs.getSinkDefinition(), neighbor, abs.getSinkStmt() )
                    task = self.getTaintPathTask( neighbor_at_sink )
                    if task is not None:
                        executor.execute( task )

            if pathConfig.getSequentialPathProcessing():
                try:
                    executor.awaitCompletion()
                    executor.reset()
                except InterruptedError as ex:
                    logger.error( "Could not wait for path executor completion", ex )

        for listener in notificationListeners:
            listener.notifySolverTerminated( self )

    def SourceFindingTask(self, abstraction):
        paths = self.path_cache.get( abstraction )
        pred = abstraction.getPredecessor()

        if pred is not None:
            for scap in paths:
                if self.processPredecessor( scap, pred ):
                    if not isKilled():
                        self.SourceFindingTask( neighbor )

                if pred.getNeighbors() is not None:
                    for neighbor in pred.getNeighbors():
                        if self.processPredecessor( scap, neighbor ):
                            if not isKilled():
                                self.SourceFindingTask( neighbor )

    def processPredecessor(self, scap, pred):
        extendedScap = scap.extend_path( pred, pathConfig )
        if extendedScap == None:
            return False

        self.checkForSource( pred, extendedScap )

        maxPaths = pathConfig.getMaxPathsPerAbstraction()
        if maxPaths > 0:
            existingPaths = self.path_cache.get( pred )
            if existingPaths is not None and existingPaths.size() > maxPaths:
                return False

        return self.path_cache.put( pred, extendedScap )

    def checkForSource(self, abs, scap):
        if abs.getPredecessor() is not None:
            return False

        assert abs.getSourceContext() is not None
        assert abs.getNeighbors() == None

        sourceContext = abs.getSourceContext()
        results.addResult( scap.getDefinition(), scap.getAccessPath(), scap.getStmt(), sourceContext.getDefinition(),
                           sourceContext.getAccessPath(), sourceContext.getStmt(), sourceContext.getUserData(),
                           scap.getAbstractionPath() )
        return True

    def getTaintPathTask(self, abs):
        scap = SourceContextAndPath( abs.getSinkDefinition(),
                                     abs.getAbstraction().getAccessPath(), abs.getSinkStmt() )
        scap = scap.extend_path( abs.getAbstraction(), pathConfig )
        if self.path_cache.put( abs.getAbstraction(), scap ):
            if not self.checkForSource( abs.getAbstraction(), scap ):
                return self.SourceFindingTask( abs.getAbstraction() )
        return None

    def triggerComputationForNeighbors(self):
        return True

    def runIncrementalPathCompuation(self):
        incrementalAbs = set()
        for abs in self.path_cache.keySet():
            for scap in self.path_cache.get( abs ):
                if abs.getNeighbors() is not None and abs.getNeighbors().size() is not scap.getNeighborCounter():
                    scap.setNeighborCounter( abs.getNeighbors().size() )

                    for neighbor in abs.getNeighbors():
                        incrementalAbs.add( AbstractionAtSink( scap.getDefinition(), neighbor, scap.getStmt() ) )

        if len( incrementalAbs.isEmpty() ) > 0:
            self.compute_taint_paths( incrementalAbs )



