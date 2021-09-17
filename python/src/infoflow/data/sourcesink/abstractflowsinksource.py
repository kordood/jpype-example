from ...data.summary.sourcesinktype import SourceSinkType
from ...methodsummary.xml.xmlconstants import XMLConstants


class AbstractFlowSinkSource:

    def __init__(self, type, parameter_idx, base_type, access_path=None, gap=None, user_data=None, match_strict=None):
        self.type = type
        self.parameter_idx = parameter_idx
        self.base_type = base_type
        self.access_path = access_path
        self.gap = gap
        self.user_data = user_data
        self.match_strict = match_strict

    def is_coarser_than(self, other):
        if self == other:
            return True

        if self.type != other.type or self.parameter_idx != other.parameter_id or not \
                self.safe_compare(self.base_type, other.base_type) or not self.safe_compare(self.gap, other.gap):
            return False
        if self.access_path is not None and other.access_path is not None:
            if self.access_path.length() > other.access_path.length():
                return False
            for i in range(0, len(self.access_path)):
                if not self.access_path.get_field(i) == other.access_path.get_field(i):
                    return False

        return True

    def is_parameter(self):
        return self.type == SourceSinkType.Parameter

    def is_this(self):
        return self.type == SourceSinkType.Field and not self.has_access_path()

    def is_custom(self):
        return self.type == SourceSinkType.Custom

    def is_field(self):
        return self.type == SourceSinkType.Field

    def is_return(self):
        return self.type == SourceSinkType.Return

    def is_gap_base_object(self):
        return self.type == SourceSinkType.GapBaseObject

    def has_access_path(self):
        return self.access_path is not None and not self.access_path.is_empty()

    def get_access_path_length(self):
        return 0 if self.access_path is None else len(self.access_path)

    def has_gap(self):
        return self.gap is not None

    def get_last_field_type(self):
        if self.access_path is None or self.access_path.is_empty():
            return self.base_type
        return self.access_path.get_last_field_type()

    def __eq__(self, other):
        if self == other:
            return True
        if other is None:
            return False
        if self.access_path is None:
            if other.access_path is not None:
                return False
        elif not self.access_path == other.access_path:
            return False
        if self.base_type is None:
            if other.base_type is not None:
                return False
        elif not self.base_type == other.base_type:
            return False
        if self.gap is None:
            if other.gap is not None:
                return False
        elif not self.gap == other.gap:
            return False
        if self.match_strict != other.match_strict:
            return False
        if self.parameter_idx != other.parameter_idx:
            return False
        if type != other.type:
            return False
        if self.user_data is None:
            if other.user_data is not None:
                return False
        elif not self.user_data == other.user_data:
            return False
        return True

    @staticmethod
    def safe_compare(o1, o2):
        if o1 is None:
            return o2 is None
        if o2 is None:
            return o1 is None
        return o1 == o2

    def xml_attributes(self):
        res = dict()
        if self.is_parameter():
            res[XMLConstants.ATTRIBUTE_FLOWTYPE] = XMLConstants.VALUE_PARAMETER
            res[XMLConstants.ATTRIBUTE_PARAMTER_INDEX] = self.parameter_idx + ""
        elif self.is_field():
            res[XMLConstants.ATTRIBUTE_FLOWTYPE] = XMLConstants.VALUE_FIELD
        elif self.is_return():
            res[XMLConstants.ATTRIBUTE_FLOWTYPE] = XMLConstants.VALUE_RETURN
        else:
            raise RuntimeError("Invalid source type")

        if self.base_type is not None:
            res[XMLConstants.ATTRIBUTE_BASETYPE] = self.base_type
        if self.has_access_path():
            res[XMLConstants.ATTRIBUTE_ACCESSPATH] = str(self.access_path)
        if self.gap is not None:
            res[XMLConstants.ATTRIBUTE_GAP] = self.gap().id + ""

        return res

    def replace_gaps(self, replacement_map):
        pass
