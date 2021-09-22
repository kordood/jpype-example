from .abstractsourcesinkinfo import AbstractSourceSinkInfo


class SinkInfo(AbstractSourceSinkInfo):

    def __init__(self, definition, user_data=None):
        super().__init__(definition, user_data)