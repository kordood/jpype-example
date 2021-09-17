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
        """

        :param list res:
        :return:
        """
        if res is None or len(res) <= 0:
            return

        logger.info("Obtainted {} connections between sources and sinks", len(res))

        cur_res_idx = 0
        for abstraction in res:
            if self.kill_flag is not None:
                res.clear()
                break

            cur_res_idx += 1
            logger.info("Building path %d..." % cur_res_idx)
            self.get_taint_path_task(abstraction)

            if self.trigger_computation_for_neighbors() and abstraction.abstraction.neighbors is not None:
                for neighbor in abstraction.abstraction.neighbors:
                    neighbor_at_sink = AbstractionAtSink(abstraction.sinkDefinition, neighbor, abstraction.sinkStmt)
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

    def check_for_source(self, abstraction, scap):
        if abstraction.predecessor is not None:
            return False

        assert abstraction.getSourceContext() is not None
        assert abstraction.neighbors is None

        source_context = abstraction.source_context
        self.results.add_result(scap.definition, scap.access_path, scap.stmt, source_context.definition,
                                source_context.access_path, source_context.stmt, source_context.user_data,
                                scap.get_abstraction_path())
        return True

    def get_taint_path_task(self, abstraction):
        scap = SourceContextAndPath(abstraction.sinkDefinition,
                                     abstraction.abstraction.access_path, abstraction.sinkStmt)
        scap = scap.extend_path(abstraction.abstraction, self.path_config)
        self.path_cache[abstraction.abstraction] = scap
        if not self.check_for_source(abstraction.abstraction, scap):
            self.source_finding_task(abstraction.abstraction)

    @staticmethod
    def trigger_computation_for_neighbors():
        return True

    def run_incremental_path_compuation(self):
        incremental_abs = set()
        for abstraction in self.path_cache.keys():
            for scap in self.path_cache.get(abstraction):
                if abstraction.neighbors is not None and abstraction.neighbors.size() is not len(scap.neighbors):
                    scap.setNeighborCounter(abstraction.neighbors.size())

                    for neighbor in abstraction.neighbors:
                        incremental_abs.add(AbstractionAtSink(scap.definition, neighbor, scap.stmt))

        if len(incremental_abs) > 0:
            self.compute_taint_paths(incremental_abs)
