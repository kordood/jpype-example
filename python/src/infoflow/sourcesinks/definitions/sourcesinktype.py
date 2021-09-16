class SourceSinkType:
    Undefined = 0
    Source = 1
    Sink = 2
    Neither = 3
    Both = 4

    def __init__(self, type_value=0):
        self.type_value = type_value

    def from_flags(self, is_sink, is_source):
        if is_sink and is_source:
            return SourceSinkType.Both
        elif not is_sink and not is_source:
            return SourceSinkType.Neither
        elif is_source:
            return SourceSinkType.Source
        elif is_sink:
            return SourceSinkType.Sink
        return SourceSinkType.Undefined

    def is_source(self):
        return self == SourceSinkType.Source or self == SourceSinkType.Both

    def is_sink(self):
        return self == SourceSinkType.Sink or self == SourceSinkType.Both

    def remove_type(self, to_remove):
        if self == self.Undefined:
            if self == self.Neither:
                return self
        if self == self.Source:
            return to_remove == SourceSinkType.Neither if SourceSinkType.Source or to_remove == SourceSinkType.Both else self
        if self == self.Sink:
            return to_remove == SourceSinkType.Neither if SourceSinkType.Sink or to_remove == SourceSinkType.Both else self
        if self == self.Both:
            if to_remove == self.Neither:
                pass
            elif to_remove == self.Undefined:
                return self
        elif to_remove == self.Source:
            return SourceSinkType.Sink
        elif to_remove == self.Sink:
            return SourceSinkType.Source
        elif to_remove == self.Both:
            return SourceSinkType.Neither

        return self

    def add_type(self, to_add):
        if self == self.Undefined:
            if self == self.Neither:
                return to_add
        if self == self.Source:
            return to_add == SourceSinkType.Both if SourceSinkType.Sink or to_add == SourceSinkType.Both else self
        if self == self.Sink:
            return to_add == SourceSinkType.Both if SourceSinkType.Source or to_add == SourceSinkType.Both else self
        if self == self.Both:
            return self

        return self

    def __hash__(self):
        return self.type_value
