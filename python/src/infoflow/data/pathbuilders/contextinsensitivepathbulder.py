import logging

from ..abstractionatsink import AbstractionAtSink
from ..sourcecontextandpath import SourceContextAndPath
from ...results.infoflowresults import InfoflowResults

logger = logging.getLogger(__file__)


class ContextInsensitivePathBuilder:

    def __init__(self):
        self.path_cache = dict()
        self.results = InfoflowResults()
        self.notification_listeners = set()
        self.kill_flag = None
        self.path_config = None

    def compute_taint_paths(self, res):
        if res is None or res.isEmpty():
            return

        logger.info("Obtainted {} connections between sources and sinks", res.size())

        cur_res_idx = 0
        for abs in res:
            if self.kill_flag is not None:
                res.clear()
                break

            cur_res_idx += 1
            logger.info("Building path %d..." % cur_res_idx)
            self.get_taint_path_task(abs)

            if self.trigger_computation_for_neighbors() and abs.abstraction.neighbors is not None:
                for neighbor in abs.abstraction.neighbors:
                    neighbor_at_sink = AbstractionAtSink(abs.sinkDefinition, neighbor, abs.sinkStmt)
                    self.get_taint_path_task(neighbor_at_sink)

    def source_finding_task(self, abstraction):
        paths = self.path_cache.get(abstraction)
        pred = abstraction.predecessor

        if pred is not None:
            for scap in paths:
                if self.process_predecessor(scap, pred):
                    self.source_finding_task(pred)

                if pred.neighbors is not None:
                    for neighbor in pred.neighbors:
                        if self.process_predecessor(scap, neighbor):
                            self.source_finding_task(neighbor)

    def process_predecessor(self, scap, pred):
        extended_scap = scap.extend_path(pred, self.path_config)
        if extended_scap is None:
            return False

        self.check_for_source(pred, extended_scap)

        max_paths = self.path_config.getMaxPathsPerAbstraction()
        if max_paths > 0:
            existing_paths = self.path_cache.get(pred)
            if existing_paths is not None and existing_paths.size() > max_paths:
                return False

        self.path_cache[pred] = extended_scap
        return True

    def check_for_source(self, abs, scap):
        if abs.predecessor is not None:
            return False

        assert abs.getSourceContext() is not None
        assert abs.neighbors is None

        source_context = abs.souce_context
        self.results.add_result(scap.definition, scap.access_path, scap.stmt, source_context.definition,
                                source_context.access_path, source_context.stmt, source_context.user_data,
                                scap.get_abstraction_path())
        return True

    def get_taint_path_task(self, abs):
        scap = SourceContextAndPath(abs.sinkDefinition,
                                     abs.abstraction.access_path, abs.sinkStmt)
        scap = scap.extend_path(abs.abstraction, self.path_config)
        if self.path_cache.put(abs.abstraction, scap):
            if not self.check_for_source(abs.abstraction, scap):
                self.source_finding_task(abs.abstraction)

    def trigger_computation_for_neighbors(self):
        return True

    def run_incremental_path_compuation(self):
        incremental_abs = set()
        for abs in self.path_cache.keySet():
            for scap in self.path_cache.get(abs):
                if abs.neighbors is not None and abs.neighbors.size() is not len(scap.neighbors):
                    scap.setNeighborCounter(abs.neighbors.size())

                    for neighbor in abs.neighbors:
                        incremental_abs.add(AbstractionAtSink(scap.definition, neighbor, scap.stmt))

        if len(incremental_abs.isEmpty()) > 0:
            self.compute_taint_paths(incremental_abs)



