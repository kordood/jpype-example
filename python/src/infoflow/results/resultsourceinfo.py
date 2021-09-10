from ..infoflowconfiguration import InfoflowConfiguration
from .abstractresultsourcesinkinfo import AbstractResultSourceSinkInfo


class ResultSourceInfo(AbstractResultSourceSinkInfo):

    def __init__(self, definition, source, context, user_data=None, path=None, path_aps=None):
        super().__init__(definition, source, context, user_data)

        self.path = path
        self.path_aps = path_aps

    def __eq__(self, other):
        if self == other:
            return True
        other = other
        if not InfoflowConfiguration().pathAgnosticResults:
            if self.path != other.path:
                return False
            if self.path_aps != other.path_aps:
                return False
    
        return True



