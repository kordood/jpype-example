class GapDefinition:

    def __init__(self, id, signature=None):
        self.id = id
        self.signature = signature

    def renumber(self, new_id):
        return GapDefinition(new_id, self.signature)

    def equals(self, obj):
        if self == obj:
            return True
        if obj is None:
            return False
        other = obj
        if id != other.id:
            return False
        if self.signature is None:
            if other.signature is not None:
                return False
        elif self.signature != other.signature:
            return False
        return True
