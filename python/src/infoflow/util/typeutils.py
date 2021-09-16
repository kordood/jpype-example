import ArrayType
import BooleanType
import ByteType
import CharType
import DoubleType
import FloatType
import IntType
import LongType
import PrimType
import RefType
import Scene
import ShortType


class TypeUtils:

    def __init__(self, manager):
        self.manager = manager

    def is_string_type(self, tp):
        if not isinstance(tp, RefType):
            return False

        ref_type = tp
        return ref_type.cls.name == "java.lang.String"

    @staticmethod
    def is_object_like_type(tp):
        if not isinstance(tp, RefType):
            return False

        rt = tp
        class_name = rt.cls.name
        return class_name == "java.lang.Object" or class_name == "java.io.Serializable" \
               or class_name == "java.lang.Cloneable"

    def check_cast(self, dest_type=None, source_type=None, access_path=None, _type=None):
        if dest_type and source_type:
            if not self.manager.config.enableTypeChecking:
                return True

            if source_type is None:
                return True

            if source_type == dest_type:
                return True

            hierarchy = self.manager.getHierarchy()
            if hierarchy is not None:
                if hierarchy.canStoreType(dest_type, source_type) or \
                        self.manager.getHierarchy().canStoreType(source_type, dest_type):
                    return True

            if isinstance(dest_type, PrimType) and isinstance(source_type, PrimType):
                return True

            return False

        elif access_path and _type:
            if not self.manager.config.enableTypeChecking:
                return True

            field_start_idx = 0
            if access_path.isStaticFieldRef():
                if not self.check_cast(_type, access_path.getFirstFieldType()):
                    return False

                if self.is_primitive_array(_type):
                    if access_path.getFieldCount() > 1:
                        return False
                field_start_idx = 1
            else:
                if not self.check_cast( _type, access_path.base_type ):
                    return False

                if self.is_primitive_array(_type):

                    if not access_path.isLocal():
                        return False

            if access_path.isFieldRef() and access_path.getFieldCount() > field_start_idx:
                if not self.check_cast(_type, access_path.getFields()[field_start_idx].getDeclaringClass().type):
                    return False

            return True

    def is_primitive_array(self, _type):
        if isinstance(_type, ArrayType):
            at = _type
            if isinstance(at.getArrayElementType(), PrimType):
                return True

        return False

    def has_compatible_types_for_call(self, ap_base, dest):
        if not self.manager.config.enableTypeChecking:
            return True

        if isinstance( ap_base.base_type, PrimType ):
            return False

        if isinstance( ap_base.base_type, ArrayType ):
            return dest.getName() == "java.lang.Object"

        return self.check_cast(ap_base, dest.type)

    def getMorePreciseType(self, tp1, tp2):
        fast_hierarchy = Scene.v().getOrMakeFastHierarchy()

        if tp1 is None:
            return tp2
        elif tp2 is None:
            return tp1
        elif tp1 == tp2:
            return tp1
        elif TypeUtils.is_object_like_type(tp1):
            return tp2
        elif TypeUtils.is_object_like_type(tp2):
            return tp1
        elif isinstance(tp1, PrimType) and isinstance(tp2, PrimType):
            return tp1
        elif fast_hierarchy.canStoreType(tp2, tp1):
            return tp2
        elif fast_hierarchy.canStoreType(tp1, tp2):
            return tp1
        else:
            if isinstance(tp1, ArrayType) and isinstance(tp2, ArrayType):
                at1 = tp1
                at2 = tp2
                if at1.numDimensions != at2.numDimensions:
                    return None
                precise_type = self.get_more_precise_type(at1.getElementType(), at2.getElementType())
                if precise_type is None:
                    return None

                return ArrayType.v(precise_type, at1.numDimensions)
            elif isinstance(tp1, ArrayType):
                at = tp1
                return self.get_more_precise_type(at.getElementType(), tp2)
            elif isinstance(tp2, ArrayType):
                at = tp2
                return self.get_more_precise_type(tp1, at.getElementType())

        return None

    def get_more_precise_type(self, tp1, tp2):
        new_type = self.get_more_precise_type(self.get_type_from_string(tp1), self.get_type_from_string(tp2))
        return None if new_type is None else "" + new_type

    @staticmethod
    def get_type_from_string(_type):
        if _type is None or _type.isEmpty():
            return None

        num_dimensions = 0
        while _type.endsWith("[]"):
            num_dimensions += 1
            _type = _type[:len(_type)-2]

        if _type == "int":
            t = IntType.v()
        elif _type == "long":
            t = LongType.v()
        elif _type == "float":
            t = FloatType.v()
        elif _type == "double":
            t = DoubleType.v()
        elif _type == "boolean":
            t = BooleanType.v()
        elif _type == "char":
            t = CharType.v()
        elif _type == "short":
            t = ShortType.v()
        elif _type == "byte":
            t = ByteType.v()
        else:
            if Scene.v().containsClass(_type):
                t = RefType.v(_type)
            else:
                return None

        if num_dimensions == 0:
            return t
        return ArrayType.v(t, num_dimensions)

    def build_array_or_add_dimension(self, _type, array_type):
        if not isinstance(_type, ArrayType):
            return array_type

        if isinstance(_type, ArrayType):
            array = _type
            if array.numDimensions >= 3:
                return None
            return array.makeArrayType()
        else:
            return ArrayType.v(_type, 1)
