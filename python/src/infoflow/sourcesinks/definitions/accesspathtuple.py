import PrimType
import RefType
import Scene

from .sourcesinktype import SourceSinkType
from ...data.accesspath import ArrayTaintType
from ...data.summary.sourcesinktype import SourceSinkType
from ...util.typeutils import TypeUtils


class AccessPathTuple:

    def __init__(self, base_type=None, fields=None, field_types=None, sink_source=None, original=None):
        """

        :param str base_type:
        :param list[str] fields:
        :param list[str] field_types:
        :param SourceSinkType sink_source:
        :param AccessPathTuple original:
        """
        if original is None:
            self.base_type = base_type
            self.fields = fields
            self.field_types = field_types
            self.sink_source = sink_source
        else:
            self.base_type = original.base_type
            self.fields = original.fields
            self.field_types = original.fields
            self.sink_source = original.sink_source
            self.description = original.description

        self.SOURCE_TUPLE = None
        self.SINK_TUPLE = None

    def create(self, is_source, is_sink):
        return self.from_path_elements(None, None, is_source, is_sink)

    @staticmethod
    def from_path_elements(base_type=None, fields=None, field_types=None, is_source=None, is_sink=None,
                           sink_source=None):
        if sink_source is None:
            sink_source = SourceSinkType.from_flags(is_source)
        fields = None if fields is None or fields.is_empty() else fields
        field_types = None if field_types is None or field_types.is_empty() else field_types

        return AccessPathTuple(base_type, fields, field_types, sink_source)

    def get_blank_source_tuple(self):
        if self.SOURCE_TUPLE is None:
            self.SOURCE_TUPLE = AccessPathTuple(self.create(True, False))
        return self.SOURCE_TUPLE

    def get_blank_sink_tuple(self):
        if self.SINK_TUPLE is None:
            self.SINK_TUPLE = AccessPathTuple(self.create(False, True))
        return self.SINK_TUPLE

    def __eq__(self, other):
        if other is None:
            return False
        if self.base_type is None:
            if other.baseType is not None:
                return False
        elif not self.base_type.__eq__(other.baseType):
            return False
        if self.description is None:
            if other.description is not None:
                return False
        elif not self.description.__eq__(other.description):
            return False
        if not self.field_types == other.fieldTypes:
            return False
        if not self.fields == other.fields:
            return False
        if self.sink_source != other.sinkSource:
            return False
        return True

    def to_access_path(self, base_val, manager, can_have_immutable_aliases):
        if isinstance(base_val.type, PrimType) or self.fields is None or self.fields.length == 0:
            return manager.getAccessPathFactory().createAccessPath(base_val, None, None, None, True, False, True,
                                                                   ArrayTaintType.ContentsAndLength,
                                                                   can_have_immutable_aliases)

        base_type = None if self.base_type is None or self.base_type.is_empty() else RefType.v(self.base_type)
        base_class = base_val.type.getSootClass() if self.base_type is None else self.base_type.getSootClass()

        fields = list()
        for i in range(0, self.fields.length):
            field_name = self.fields[i]
            last_field_type = base_class.type if i == 0 else TypeUtils.get_type_from_string(self.field_types[i - 1])
            if not isinstance(last_field_type, RefType):
                raise RuntimeError("Type %s cannot have fields (requested: %s)" % (str(last_field_type), field_name))
            last_field_class = last_field_type.getSootClass()

            field_type = TypeUtils.get_type_from_string(self.field_types[i])
            fld = last_field_class.getFieldUnsafe(field_name, field_type)
            if fld is None:
                fld = last_field_class.getFieldUnsafe(field_name, field_type)
                if fld is None:
                    f = Scene.v().makeSootField(field_name, field_type, 0)
                    f.setPhantom(True)
                    fld = last_field_class.getOrAddField(f)

            if fld is None:
                return None
            fields[i] = fld

        return manager.getAccessPathFactory().createAccessPath(base_val, fields, base_type, None, True, False, True,
                                                               ArrayTaintType.ContentsAndLength,
                                                               can_have_immutable_aliases)
