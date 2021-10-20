from .abstractsourcesinkdefinition import AbstractSourceSinkDefinition
from .accesspathtuple import AccessPathTuple


class FieldSourceSinkDefinition(AbstractSourceSinkDefinition):

    def __init__(self, field_signature, access_paths=None, category=None):
        """

        :param field_signature:
        :param list[AccessPathTuple] access_paths:
        :param category:
        """
        super().__init__(category)
        self.field_signature = field_signature
        self.access_paths = access_paths

    def get_source_only_definition(self):
        sources = None
        if self.access_paths is not None:
            sources = list()
            for apt in self.access_paths:
                if apt.sink_source.is_source():
                    sources.append(apt)

        return self.build_new_definition(sources)

    def get_sink_only_definition(self):
        sinks = None
        if self.access_paths is not None:
            sinks = list()
            for apt in self.access_paths:
                if apt.sink_source.is_sink():
                    sinks.append(apt)

        return self.build_new_definition(sinks)

    def build_new_definition(self, field_signature=None, access_paths=None):
        if field_signature is None:
            field_signature = self.field_signature
        fssd = FieldSourceSinkDefinition(field_signature, access_paths)
        fssd.category = self.category
        return fssd

    def merge(self, other):
        if isinstance(other, FieldSourceSinkDefinition):
            other_field = other

            if other_field.access_paths is not None and len(other_field.access_paths) > 0:
                if self.access_paths is None:
                    self.access_paths = list()
                for apt in other_field.access_paths:
                    self.access_paths.append(apt)

    def filter(self, to_filter):
        filtered_aps = None
        if self.access_paths is not None and len(self.access_paths) > 0:
            filtered_aps = list()
            for ap in self.access_paths:
                if to_filter.contains(ap):
                    filtered_aps.append(ap)

        define = self.build_new_definition(self.field_signature, filtered_aps)
        define.category = self.category
        return define

    def is_empty(self):
        return self.access_paths is None or not len(self.access_paths) > 0

    def __eq__(self, other):
        if self == other:
            return True
        if not super().__eq__(other):
            return False
        if self.access_paths is None:
            if other.access_paths is not None:
                return False
        elif not self.access_paths.__eq__(other.access_paths):
            return False
        if self.field_signature is None:
            if other.field_signature is not None:
                return False
        elif not self.field_signature.__eq__(other.field_signature):
            return False
        return True
