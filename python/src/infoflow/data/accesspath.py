from __future__ import annotations
import Jimple
import NoneType
from ...infoflow.sootir.soot_value import SootLocal
from ...infoflow.sootir.soot_value import SootInstanceFieldRef
from ...infoflow.sootir.soot_value import SootStaticFieldRef
from ...infoflow.sootir.soot_value import SootArrayRef

from __future__ import annotations

class ArrayTaintType:
    Contents = 0
    Length = 1
    ContentsAndLength = 2


class AccessPath:

    def __init__(self, val: Local = None, appending_fields: list = None, val_type=None, appending_field_types: list =None, taint_sub_fields: bool=True,
                 is_cut_off_approximation: bool = False, array_taint_type: ArrayTaintType = None, can_have_immutable_aliases: bool =False):
        self.value = val
        self.fields = appending_fields
        self.baseType = val_type
        self.fieldTypes = appending_field_types
        self.taint_sub_fields = taint_sub_fields
        self.cutOffApproximation = is_cut_off_approximation
        self.array_taint_type = array_taint_type if array_taint_type else ArrayTaintType.ContentsAndLength
        self.can_have_immutable_aliases = can_have_immutable_aliases

        self.array_taint_type = ArrayTaintType
        self.zeroAccessPath = None
        self.emptyAccessPath = AccessPath()

    @staticmethod
    def can_contain_value(val):
        if val is None:
            return False

        return isinstance(val, Local) or isinstance(val, InstanceFieldRef) or isinstance(val, StaticFieldRef) \
               or isinstance(val, ArrayRef)

    def get_complete_value(self):
        f = self.get_first_field()
        if self.value is None:
            if f is None:
                return None

            return Jimple.v().newStaticFieldRef(f.makeRef())
        else:
            if f is None:
                return self.value
            return Jimple.v().newInstanceFieldRef(self.value, f.makeRef())

    def get_last_field(self):
        if self.fields is None or len(self.fields) == 0:
            return None
        return self.fields[len(self.fields) - 1]

    def get_last_field_type(self):
        if self.fieldTypes is None or len(self.fieldTypes) == 0:
            return self.baseType
        return self.fieldTypes[len(self.fieldTypes) - 1]

    def get_first_field(self):
        if self.fields is None or len(self.fields) == 0:
            return None
        return self.fields[0]

    def first_field_matches(self, field):
        if self.fields is None or len(self.fields) == 0:
            return False
        if field == self.fields[0]:
            return True
        return False

    def get_first_field_type(self):
        if self.fieldTypes is None or len(self.fieldTypes) == 0:
            return None
        return self.fieldTypes[0]

    def get_field_count(self):
        return 0 if self.fields is None else len(self.fields)

    def __eq__(self, other):
        if other == self:
            return True
        if other is None:
            return False

        if self.value is None:
            if other.value is not None:
                return False
        elif not self.value == other.value:
            return False
        if self.baseType is None:
            if other.baseType is not None:
                return False
        elif not self.baseType == other.baseType:
            return False

        if self.fields != other.fields:
            return False
        if self.fieldTypes != other.fieldTypes:
            return False

        if self.taint_sub_fields != other.taint_sub_fields:
            return False
        if self.array_taint_type != other.array_taint_type:
            return False

        if self.can_have_immutable_aliases != other.can_have_immutable_aliases:
            return False

        return True

    def is_static_field_ref(self):
        return self.value is None and self.fields is not None and len(self.fields) > 0

    def is_instance_field_ref(self):
        return self.value is not None and self.fields is not None and len(self.fields) > 0

    def is_field_ref(self):
        return self.fields is not None and len(self.fields) > 0

    def is_local(self):
        return self.value is not None and isinstance(self.value, Local) and (self.fields is None or len(self.fields) == 0)

    def clone(self):
        if self == self.emptyAccessPath:
            return self

        a = AccessPath(self.value, self.fields, self.baseType, self.fieldTypes, self.taint_sub_fields,
                       self.cutOffApproximation, self.array_taint_type, self.can_have_immutable_aliases)
        return a

    def is_empty(self):
        return self.value is None and (self.fields is None or len(self.fields) == 0)

    def entails(self, a2: AccessPath):
        if self.is_empty() or a2.is_empty():
            return False

        if (self.value is not None and a2.value is None) or (self.value is None and a2.value is not None):
            return False

        if self.value is not None and not self.value == a2.value:
            return False

        if self.fields is not None and a2.fields is not None:
            if len(self.fields) > a2.len(self.fields):
                return False

            for i in range(0, len(self.fields)):
                if not self.fields[i] == a2.fields[i]:
                    return False

        return True

    def drop_last_field(self):
        if self.fields is None or len(self.fields) == 0:
            return self

        new_fields = None
        new_types = None
        if len(self.fields) > 1:
            new_fields = self.fields[:-1]
            new_types = self.fieldTypes[:-1]

        return AccessPath(self.value, new_fields, self.baseType, new_types, self.taint_sub_fields,
                          self.cutOffApproximation, self.array_taint_type, self.can_have_immutable_aliases)

    def is_cut_off_approximation(self):
        return self.cutOffApproximation

    def starts_with(self, val):
        if not self.can_contain_value( val ):
            return False

        if isinstance(val, Local) and self.value == val:
            return True
        elif isinstance(val, StaticFieldRef):
            return self.value is None and self.fields is not None and len(self.fields) > 0 \
                   and self.fields[0] == val.get_field()
        elif isinstance(val, InstanceFieldRef):
            iref = val
            return self.value == iref.getBase() and self.fields is not None and len(self.fields) > 0 \
                   and self.fields[0] == iref.get_field()
        else:
            return False

    def get_zero_access_path(self):
        zero_access_path = None
        if self.zeroAccessPath is None:
            zero_access_path = AccessPath(Jimple.v().newLocal("zero", NoneType.v()), None, NoneType.v(), None, False,
                                          False, self.array_taint_type.ContentsAndLength, False)
        return zero_access_path
