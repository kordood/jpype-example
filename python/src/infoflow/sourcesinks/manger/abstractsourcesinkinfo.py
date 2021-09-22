class AbstractSourceSinkInfo:

    def __init__(self, definition, user_data=None):
        self.definition = definition
        self.user_data = user_data

    def __eq__(self, other):
        if other is None:
            return False
        if self.definition is None:
            if other.definition is not None:
                return False
        elif not self.definition.__eq__(other.definition):
            return False
        if self.user_data is None:
            if other.userData is not None:
                return False
        elif not self.user_data.__eq__(other.userData):
            return False
        return True
