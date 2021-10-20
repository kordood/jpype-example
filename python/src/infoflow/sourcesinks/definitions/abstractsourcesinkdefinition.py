class AbstractSourceSinkDefinition:

    def __init__(self, category):
        """

        :param ISourceSinkCategory category:
        """
        self.category = category

    def __eq__(self, other):
        if self == other:
            return True
        if other is None:
            return False
        other = other
        if self.category is None:
            if other.category is not None:
                return False
        elif not self.category.__eq__(other.category):
            return False
        return True

    def is_empty(self):
        pass
