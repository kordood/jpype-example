import logging

logger = logging.getLogger(__file__)


class BatchPathBuilder(AbstractAbstractionPathBuilder):

    def __init__(self, manager, inner_builder):
        super(manager)
        self.batch_size = 5
        self.inner_builder = inner_builder

    def compute_taint_paths(self, res):
        batch = set()

        self.inner_builder.reset()
        self.inner_builder.compute_taint_paths(batch)

    def get_results(self):
        return self.inner_builder.get_results()

    def run_incremental_path_compuation(self):
        self.inner_builder.run_incremental_path_compuation()

    def force_terminate(self, reason):
        self.inner_builder.force_terminate(reason)

    def is_terminated(self):
        return self.inner_builder.is_terminated()

    def is_killed(self):
        return self.inner_builder.is_killed()

    def reset(self):
        self.inner_builder.reset()

    def add_status_listener(self, listener):
        self.inner_builder.add_status_listener(listener)
