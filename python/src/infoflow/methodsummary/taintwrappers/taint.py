from ...data.sourcesink.flowsink import FlowSink


class Taint(FlowSink):

    def __init__(self, type, paramter_idx, base_type, access_path, taint_sub_fields=None, gap=False):
        super().__init__(type, paramter_idx, base_type, access_path, taint_sub_fields, gap)
