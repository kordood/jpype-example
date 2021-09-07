from .abstractresultsourcesinkinfo import AbstractResultSourceSinkInfo


class ResultSinkInfo(AbstractResultSourceSinkInfo):

    def __init__(self, definition, access_path, stmt, user_data=None):
        super().__init__(definition, access_path, stmt, user_data)
