from .abstractsourcesinkinfo import AbstractSourceSinkInfo
from ...data.accesspath import AccessPath


class SourceInfo(AbstractSourceSinkInfo):

    def __init__(self, definition, user_data, access_paths=None):
        super().__init__(definition, user_data)
        if isinstance(access_paths, AccessPath):
            access_paths = [access_paths]
        self.access_paths = access_paths

    def __eq__(self, other):
        if not super().__eq__(other):
            return False
        if self.access_paths is None:
            if other.accessPaths is not None:
                return False
        elif not self.access_paths.__eq__(other.accessPaths):
            return False
        return True
