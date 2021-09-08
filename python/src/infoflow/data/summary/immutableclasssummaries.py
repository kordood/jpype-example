from .classsummaries import ClassSummaries


class ImmutableClassSummaries(ClassSummaries):

    def add_dependency(self, class_name):
        raise RuntimeError("This object is immutable")

    def clear(self):
        raise RuntimeError("This object is immutable")

    def merge(self, summaries=None, class_name=None, new_sums=None):
        raise RuntimeError("This object is immutable")
