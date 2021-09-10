from ..infoflowconfiguration import InfoflowConfiguration


class AbstractResultSourceSinkInfo:

    def __init__(self, definition, access_path, stmt, user_data=None):
        assert access_path is not None

        self.definition = definition
        self.access_path = access_path
        self.stmt = stmt
        self.user_data = user_data

    def __eq__(self, other):
        if self == other:
            return True

        if other is None:
            return False

        si = other
        if InfoflowConfiguration().oneResultPerAccessPath and not self.access_path == si.access_path:
            return False

        if self.definition is None:
            if si.definition is not None:
                return False
        elif not self.definition == si.definition:
            return False
        if self.stmt is None:
            if si.stmt is not None:
                return False
        elif not self.stmt == si.stmt:
            return False
        if self.user_data is None:
            if si.user_data is not None:
                return False
        elif not self.user_data == si.user_data:
            return False

        return True
