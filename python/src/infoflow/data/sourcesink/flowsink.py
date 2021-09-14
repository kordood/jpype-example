from .abstractflowsinksource import AbstractFlowSinkSource
from .invalidflowspecificationerror import InvalidFlowSpecificationError
from ..summary.sourcesinktype import SourceSinkType
from ...methodsummary.xml.xmlconstants import XMLConstants
from ...methodsummary.taintwrappers.summarytaintwrapper import AccessPathFragment
from ..summary.gapdefinition import GapDefinition

class FlowSink(AbstractFlowSinkSource):

    def __init__(self, type: SourceSinkType, paramter_idx: int, base_type: str, access_path: AccessPathFragment =None, taint_sub_fields: bool =None, taint_sub_fields2: bool =None,
                 gap: GapDefinition =False, user_data=None, match_strict: bool=False):
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

    def __eq__(self, other):
        if not super().__eq__(other):
            return False

        return self.taint_sub_fields == other.taint_sub_fields

    def validate(self, method_name: str):
        if self.type == SourceSinkType.GapBaseObject and self.gap is None:
            raise InvalidFlowSpecificationError(
                "Gap base flows must always be linked with gaps. Offending method: " + method_name, self)

        if self.type == SourceSinkType.Parameter and self.gap is None:
            raise InvalidFlowSpecificationError("Parameters may only be sinks when referencing gaps", self)

    def replace_gaps(self, replacement_map: map ):
        if self.gap is None:
            return self
        new_gap = replacement_map.get(self.gap.getID())
        if new_gap is None:
            return self
        return FlowSink(self.type, self.parameter_idx, self.base_type, self.access_path, self.taint_sub_fields,
                        new_gap, self.match_strict)
