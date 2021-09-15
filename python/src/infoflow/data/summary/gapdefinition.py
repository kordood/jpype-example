class GapDefinition:

    def __init__(self, id: int, signature: str=None):
        self.id = id
        self.signature = signature

    def renumber(self, new_id: int):
        return GapDefinition(new_id, self.signature)

    def __eq__(self, other):
        if self == other:
            return True
        if other is None:
            return False
        if id != other.id:
            return False
        if self.signature is None:
            if other.signature is not None:
                return False
        elif self.signature != other.signature:
            return False
        return True
