class InvalidFlowSpecificationError(RuntimeError):

    def __init__(self, message, sink_source):
        super(message)
        self.sinkSource = sink_source
