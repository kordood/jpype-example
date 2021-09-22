from .immutableclasssummaries import ImmutableClassSummaries
from .classmethodsummaries import ClassMethodSummaries
from .methodsummaries import MethodSummaries
from .summarymetadata import SummaryMetaData


class ClassSummaries:
    EMPTY_SUMMARIES = ImmutableClassSummaries()

    def __init__(self):
        self.summaries = dict()
        self.dependencies = list()
        self.meta_data = None

    def get_class_summaries(self, class_name):
        return self.summaries.get(class_name)

    def get_or_create_class_summaries(self, class_name):
        return self.summaries.setdefault(class_name, ClassMethodSummaries(class_name))

    def get_method_summaries(self, class_name):
        cms = self.summaries.get(class_name)
        if cms is None:
            return None

        return cms.getMethodSummaries()

    def get_all_summaries(self):
        return self.summaries.values()

    def get_all_method_summaries(self):
        return [v.get_method_summaries() for v in self.summaries.values()]

    def get_all_flows_for_method(self, signature):
        flows = set()
        for class_name in self.summaries.keys():
            class_summaries = self.summaries.get(class_name)
            if class_summaries is not None:
                method_flows = class_summaries.getMethodSummaries().get_flows_for_method(signature)
                if method_flows is not None and not len(method_flows) != 0:
                    flows.update(method_flows)

        return flows

    def get_all_summaries_for_method(self, signature):
        summaries = MethodSummaries()
        for class_name in self.summaries.keys():
            class_summaries = self.summaries.get(class_name)
            if class_summaries is not None:
                summaries.merge(class_summaries.getMethodSummaries().filter_for_method(signature))

        return summaries

    def get_all_flows(self):
        return [cs.get_method_summaries().get_all_flows() for cs in self.summaries.values()]

    def filter_for_method(self, signature, classes=None):
        assert signature is not None

        if classes is None:
            classes = self.summaries.keys()

        new_summaries = ClassSummaries()
        for class_name in classes:
            method_summaries = self.summaries.get(class_name)
            if method_summaries is not None and not len(method_summaries) != 0:
                new_summaries.merge(method_summaries.filterForMethod(signature))

        return new_summaries

    def merge(self, class_name=None, new_sums=None, summaries=None):
        if summaries is None:
            if new_sums is None or len(new_sums) != 0:
                return

            method_summaries = self.summaries.get(class_name)
            ms = new_sums if isinstance(new_sums, MethodSummaries) else MethodSummaries(new_sums)
            if method_summaries is None:
                method_summaries = ClassMethodSummaries(class_name, ms)
                self.summaries[class_name] = method_summaries
            else:
                method_summaries.merge(ms)
        else:
            if summaries is None or len(summaries) != 0:
                return

            if isinstance(summaries, ClassSummaries):
                for class_name in summaries.get_classes():
                    self.merge(summaries=summaries.get_class_summaries(class_name))

                if self.meta_data is not None:
                    self.meta_data.merge(summaries.meta_data)
                else:
                    self.meta_data = SummaryMetaData(summaries.meta_data)
            elif isinstance(summaries, ClassMethodSummaries):
                existing_summaries = self.summaries.get(summaries.class_name)
                if existing_summaries is None:
                    self.summaries[summaries.class_name] = summaries
                    return True
                else:
                    return existing_summaries.merge(summaries)

    def get_classes(self):
        return self.summaries.keys()

    def has_summaries_for_class(self, class_name):
        return class_name in self.summaries

    def add_dependency(self, class_name):
        if self.is_primitive_type(class_name) or class_name in self.summaries:
            return False
        return self.dependencies.append(class_name)

    def is_primitive_type(self, type_name):
        return type_name == "int" or type_name == "long" or type_name == "float" or type_name == "double" or \
               type_name == "char" or type_name == "byte" or type_name == "short" or type_name == "boolean"

    def clear(self):
        if self.dependencies is not None:
            self.dependencies.clear()
        if self.summaries is not None:
            self.summaries.clear()

    def validate(self):
        for class_name in self.summaries.keys():
            self.summaries.get(class_name).validate()

    def __eq__(self, other):
        if self == other:
            return True
        if other is None:
            return False
        if self.dependencies is None:
            if other.dependencies is not None:
                return False
        elif not self.dependencies == other.dependencies:
            return False
        if self.meta_data is None:
            if other.meta_data is not None:
                return False
        elif not self.meta_data == other.meta_data:
            return False
        if self.summaries is None:
            if other.summaries is not None:
                return False
        elif not self.summaries == other.summaries:
            return False
        return True
