from .methodsummaries import MethodSummaries
from .gapdefinition import GapDefinition
import collections

class ImmutableMethodSummaries(MethodSummaries):

    def add_clear(self, clear):
        raise RuntimeError("This object is immutable")

    def add_flow(self, flow):
        raise RuntimeError("This object is immutable")

    def clear(self):
        raise RuntimeError("This object is immutable")

    def create_temporary_gap(self, gap_id: int):
        raise RuntimeError("This object is immutable")

    def merge(self, new_flows: MethodSummaries):
        raise RuntimeError("This object is immutable")

    def merge_clears(self, new_clears):
        raise RuntimeError("This object is immutable")

    def merge_flows(self, new_flows ):
        raise RuntimeError("This object is immutable")

    def merge_summaries(self, new_summaries):
        raise RuntimeError("This object is immutable")

    def remove(self, to_remove):
        raise RuntimeError("This object is immutable")

    def remove_all(self, to_remove):
        raise RuntimeError("This object is immutable")

    def remove_gap(self, gap: GapDefinition):
        raise RuntimeError("This object is immutable")
