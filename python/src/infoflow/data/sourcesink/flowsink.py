from .abstractflowsinksource import AbstractFlowSinkSource
from .invalidflowspecificationerror import InvalidFlowSpecificationError
from ..summary.sourcesinktype import SourceSinkType
from ...methodsummary.xml.xmlconstants import XMLConstants


class FlowSink(AbstractFlowSinkSource):

    def __init__(self, type, paramter_idx, base_type, access_path=None, taint_sub_fields=None, taint_sub_fields2=None,
                 gap=False, user_data=None, match_strict=False):
        if taint_sub_fields2 is None:
            super().__init__(type, paramter_idx, base_type, access_path, gap, user_data, match_strict)
            self.taint_sub_fields = taint_sub_fields

        else:
            if gap is None:
                super().__init__(type, -1, base_type, access_path, match_strict)
            else:
                super().__init__(type, -1, base_type, access_path, gap, match_strict)

            self.taint_sub_fields = taint_sub_fields2 or (access_path is not None
                                                          and len(access_path) > len(access_path))

    def is_coarser_than(self, other):
        return super().is_coarser_than(other) and isinstance(other, FlowSink) and self.taint_sub_fields

    def xml_attributes(self):
        res = super().xml_attributes()
        res[XMLConstants.ATTRIBUTE_TAINT_SUB_FIELDS] = self.taint_sub_fields() + ""
        return res

    def equals(self, obj):
        if not super().equals(obj):
            return False

        return self.taint_sub_fields == obj.taint_sub_fields

    def validate(self, method_name):
        if self.type == SourceSinkType.GapBaseObject and self.gap is None:
            raise InvalidFlowSpecificationError(
                "Gap base flows must always be linked with gaps. Offending method: " + method_name, self)

        if self.type == SourceSinkType.Parameter and self.gap is None:
            raise InvalidFlowSpecificationError("Parameters may only be sinks when referencing gaps", self)

    def replace_gaps(self, replacement_map):
        if self.gap is None:
            return self
        new_gap = replacement_map.get(self.gap.getID())
        if new_gap is None:
            return self
        return FlowSink(self.type, self.parameter_idx, self.base_type, self.access_path, self.taint_sub_fields,
                        new_gap, self.match_strict)
