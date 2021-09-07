class DataFlowResult:

    def __init__(self, source, sink):
        self.source = source
        self.sink = sink

    def get_source_category_id(self):
        source_def = self.source.definition
        if source_def is not None:
            source_cat = source_def.category
            if source_cat is not None:
                return source_cat.id

        return None

    def get_sink_category_id(self):
        sink_def = self.sink.definition
        if sink_def is not None:
            sink_cat = sink_def.category
            if sink_cat is not None:
                return sink_cat.id

        return None

    def equals(self, obj):
        if self == obj:
            return True
        if obj is None:
            return False
        other = obj
        if self.sink is None:
            if other.sink is not None:
                return False
        elif not self.sink.equals(other.sink):
            return False
        if self.source is None:
            if other.source is not None:
                return False
        elif not self.source.equals(other.source):
            return False
        return True
