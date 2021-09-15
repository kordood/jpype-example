from .classsummaries import ClassSummaries


class ImmutableClassSummaries(ClassSummaries):

    def add_dependency(self, class_name: str):
        raise RuntimeError("This object is immutable")

    def clear(self):
        raise RuntimeError("This object is immutable")

    def merge(self, summaries: ClassSummaries = None, class_name: str = None, new_sums: set =None):
        raise RuntimeError("This object is immutable")
