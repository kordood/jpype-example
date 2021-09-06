from ...misc.copymember import copy_member


class SourceFindingTask:

    def __init__(self, path_builder, abstraction):
        copy_member(self, path_builder)
        self.abstraction = abstraction

    def run(self):
        paths = self.path_cache.get(self.abstraction)
        pred = self.abstraction.getPredecessor()

        if pred is not None and paths is not None:
            for scap in paths:
                if self.process_predecessor(scap, pred):
                    self.schedule_dependent_task(SourceFindingTask(pred))

                    if pred.getNeighbors() is not None:
                        for neighbor in pred.getNeighbors():
                            if self.process_predecessor(scap, neighbor):
                                self.schedule_dependent_task(SourceFindingTask(neighbor))

    def process_predecessor(self, scap, pred):
        if pred.getCurrentStmt() is not None and pred.getCurrentStmt() == pred.getCorrespondingCallSite():
            extended_scap = scap.extendPath(pred, self.path_config)
            if extended_scap is None:
                return False

            self.check_for_source(pred, extended_scap)
            return self.path_cache.put(pred, extended_scap)

        extended_scap = scap.extendPath(pred, self.path_config)
        if extended_scap is None:
            return False

        if pred.getCurrentStmt() is not None and pred.getCurrentStmt().containsInvokeExpr():
            path_and_item = extended_scap.popTopCallStackItem()
            if path_and_item is not None:
                top_call_stack_item = path_and_item.getO2()
                if top_call_stack_item != pred.getCurrentStmt():
                    return False

                extended_scap = path_and_item.getO1()

        self.check_for_source(pred, extended_scap)

        max_paths = self.path_config.getMaxPathsPerAbstraction()
        if max_paths > 0:
            existing_paths = self.path_cache.get(pred)
            if existing_paths is not None and existing_paths.size() > max_paths:
                return False

        return self.path_cache.put(pred, extended_scap)
