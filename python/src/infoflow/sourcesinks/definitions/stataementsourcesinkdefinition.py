from .abstractsourcesinkdefinition import AbstractSourceSinkDefinition
from .sourcesinktype import SourceSinkType
from .accesspathtuple import AccessPathTuple


class StatementSourceSinkDefinition(AbstractSourceSinkDefinition):

    def __init__(self, stmt, local, access_paths, category=None):
        super().__init__(category)
        self.stmt = stmt
        self.local = local
        self.access_paths = access_paths

    def get_source_only_definition(self):
        new_set = list()
        if self.access_paths is not None:
            for apt in self.access_paths:
                ss_type = apt.getSourceSinkType()
                if ss_type == SourceSinkType.Source:
                    new_set.append(apt)
                elif ss_type == SourceSinkType.Both:
                    new_set.append(AccessPathTuple(apt.getBaseType(), apt.getFields(), apt.getFieldTypes(),
                                                   SourceSinkType.Source))

        return self.build_new_definition(self.stmt, self.local, new_set)

    def get_sink_only_definition(self):
        new_set = list()
        if self.access_paths is not None:
            for apt in self.access_paths:
                ss_type = apt.getSourceSinkType()
                if ss_type == SourceSinkType.Sink:
                    new_set.append(apt)
                elif ss_type == SourceSinkType.Both:
                    new_set.append(AccessPathTuple(apt.getBaseType(), apt.getFields(), apt.getFieldTypes(),
                                                   SourceSinkType.Sink))

        return self.build_new_definition(self.stmt, self.local, new_set)

    def merge(self, other):
        if isinstance(other, StatementSourceSinkDefinition):
            other_stmt = other

            if other_stmt.access_paths is not None and len(other_stmt.access_paths) > 0:
                if self.access_paths is None:
                    self.access_paths = list()
                for apt in other_stmt.access_paths:
                    self.access_paths.append(apt)

    @staticmethod
    def is_empty():
        return False

    def filter(self, to_filter):
        filtered_aps = None
        if self.access_paths is not None and len(self.access_paths) > 0:
            filtered_aps = list()
            for ap in self.access_paths:
                if ap in to_filter:
                    filtered_aps.append(ap)

        define = self.build_new_definition(self.stmt, self.local, filtered_aps)
        define.category = self.category 
        return define

    def build_new_definition(self, stmt, local, access_paths):
        sssd = StatementSourceSinkDefinition(stmt, local, access_paths)
        sssd.category = self.category
        return sssd

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
        if self.local is None:
            if other.local is not None:
                return False
        elif not self.local.__eq__(other.local):
            return False
        if self.stmt is None:
            if other.stmt is not None:
                return False
        elif not self.stmt.__eq__(other.stmt):
            return False
        return True
