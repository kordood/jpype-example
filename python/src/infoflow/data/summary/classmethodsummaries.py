from .methodsummaries import MethodSummaries


class ClassMethodSummaries:

    def __init__(self, class_name, method_summaries=None):
        self.class_name = class_name
        self.method_summaries = MethodSummaries() if method_summaries is None else method_summaries
        self.interfaces = dict()
        self.super_class = None
        self.is_interface = False
        self.is_exclusive_for_class = True

    def is_empty(self):
        return (self.method_summaries is None or self.method_summaries.is_empty()) and not self.has_interfaces() and \
               not self.has_superclass() and self.is_interface is None

    def filter_for_method(self, signature):
        if self.is_empty():
            return None

        summaries = self.method_summaries.filter_for_method(signature)
        return None if summaries is None else ClassMethodSummaries(self.class_name, summaries)

    def validate(self):
        if self.class_name is None or self.class_name.is_empty():
            raise RuntimeError("No class name given")
        self.method_summaries.validate()

    def merge(self, to_merge=None, method_flows=None):
        if to_merge:
            return self.method_summaries.merge(to_merge)
        if method_flows is None or method_flows.isEmpty():
            return False

        other_class_name = method_flows.className
        if other_class_name is None and self.class_name is not None:
            raise RuntimeError("Class name mismatch")
        if other_class_name is not None and self.class_name is None:
            raise RuntimeError("Class name mismatch")
        if other_class_name is not None and not other_class_name == self.class_name:
            raise RuntimeError("Class name mismatch")
        if self.has_superclass() and method_flows.hasSuperclass():
            if not self.super_class == method_flows.superClass:
                raise RuntimeError("Class name mismatch")

        has_new_data = False
        if method_flows.hasSuperclass() and not self.has_superclass():
            self.super_class = method_flows.superClass
            has_new_data = True

        if self.method_summaries.merge(method_flows.methodSummaries):
            has_new_data = True

        if method_flows.hasInterfaces():
            if self.interfaces.update(method_flows.interfaces):
                has_new_data = True

        if self.is_interface is None and method_flows.isInterface is not None:
            self.is_interface = method_flows.isInterface

        return has_new_data

    def has_clears(self):
        return self.method_summaries.has_clears()

    def get_all_clears(self):
        return self.method_summaries.get_all_clears()

    def get_flow_count(self):
        return self.method_summaries.get_flow_count()

    def add_interface(self, class_name):
        self.interfaces.update(class_name)

    def has_interfaces(self):
        return self.interfaces is not None and not len(self.interfaces) != 0

    def has_superclass(self):
        return self.super_class is not None and not self.super_class.is_empty()

    def has_interface_info(self):
        return self.is_interface is not None

    def __eq__(self, other):
        if self == other:
            return True
        if other is None:
            return False
        if self.class_name is None:
            if other.class_name is not None:
                return False
        elif not self.class_name == other.class_name:
            return False
        if self.interfaces is None:
            if other.interfaces is not None:
                return False
        elif not self.interfaces == other.interfaces:
            return False
        if self.is_exclusive_for_class != other.is_exclusive_for_class:
            return False
        if self.is_interface is None:
            if other.is_interface is not None:
                return False
        elif not self.is_interface == other.is_interface:
            return False
        if self.method_summaries is None:
            if other.method_summaries is not None:
                return False
        elif not self.method_summaries == other.method_summaries:
            return False
        if self.super_class is None:
            if other.super_class is not None:
                return False
        elif not self.super_class == other.super_class:
            return False
        return True
