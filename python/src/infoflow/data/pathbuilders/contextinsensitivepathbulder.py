import logging

logger = logging.getLogger(__file__)


class ContextInsensitivePathBuilder:

    def __init__(self):
        self.path_cache = list()
        self.results = InfoflowResults()
        self.notification_listeners = set()
        self.kill_flag = None
        self.path_config = None

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
            task = self.get_taint_path_task( abs )
            if task is not None:
                executor.execute( task )

            if self.trigger_computation_for_neighbors() and abs.getAbstraction().getNeighbors() is not None:
                for neighbor in abs.getAbstraction().getNeighbors():
                    neighbor_at_sink = AbstractionAtSink( abs.getSinkDefinition(), neighbor, abs.getSinkStmt() )
                    task = self.get_taint_path_task( neighbor_at_sink )

                    if task is not None:
                        executor.execute( task )

            if self.path_config.getSequentialPathProcessing():
                try:
                    executor.awaitCompletion()
                    executor.reset()
                except InterruptedError as ex:
                    logger.error( "Could not wait for path executor completion", ex )

        for listener in notificationListeners:
            listener.notifySolverTerminated( self )

    def source_finding_task(self, abstraction):
        paths = self.path_cache.get( abstraction )
        pred = abstraction.getPredecessor()

        if pred is not None:
            for scap in paths:
                if self.process_predecessor( scap, pred ):
                    if not isKilled():
                        self.source_finding_task( neighbor )

                if pred.getNeighbors() is not None:
                    for neighbor in pred.getNeighbors():
                        if self.process_predecessor( scap, neighbor ):
                            if not isKilled():
                                self.source_finding_task( neighbor )

    def process_predecessor(self, scap, pred):
        extended_scap = scap.extend_path( pred, self.path_config )
        if extended_scap == None:
            return False

        self.check_for_source( pred, extended_scap )

        max_paths = self.path_config.getMaxPathsPerAbstraction()
        if max_paths > 0:
            existing_paths = self.path_cache.get( pred )
            if existing_paths is not None and existing_paths.size() > max_paths:
                return False

        return self.path_cache.put( pred, extended_scap )

    def check_for_source(self, abs, scap):
        if abs.getPredecessor() is not None:
            return False

        assert abs.getSourceContext() is not None
        assert abs.getNeighbors() == None

        source_context = abs.getSourceContext()
        results.addResult( scap.getDefinition(), scap.getAccessPath(), scap.getStmt(), source_context.getDefinition(),
                           source_context.getAccessPath(), source_context.getStmt(), source_context.getUserData(),
                           scap.get_abstraction_path() )
        return True

    def get_taint_path_task(self, abs):
        scap = SourceContextAndPath( abs.getSinkDefinition(),
                                     abs.getAbstraction().getAccessPath(), abs.getSinkStmt() )
        scap = scap.extend_path( abs.getAbstraction(), self.path_config )
        if self.path_cache.put( abs.getAbstraction(), scap ):
            if not self.check_for_source( abs.getAbstraction(), scap ):
                return self.source_finding_task( abs.getAbstraction() )
        return None

    def trigger_computation_for_neighbors(self):
        return True

    def run_incremental_path_compuation(self):
        incremental_abs = set()
        for abs in self.path_cache.keySet():
            for scap in self.path_cache.get( abs ):
                if abs.getNeighbors() is not None and abs.getNeighbors().size() is not scap.getNeighborCounter():
                    scap.setNeighborCounter( abs.getNeighbors().size() )

                    for neighbor in abs.getNeighbors():
                        incremental_abs.add( AbstractionAtSink( scap.getDefinition(), neighbor, scap.getStmt() ) )

        if len( incremental_abs.isEmpty() ) > 0:
            self.compute_taint_paths( incremental_abs )



