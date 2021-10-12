import logging

from .implicitflowaliasstrategy import ImplicitFlowAliasStrategy
from ...infoflow.data.accesspath import AccessPath
from ...infoflow.sootir.soot_statement import DefinitionStmt
from ...infoflow.sootir.soot_value import SootIntConstant, SootFloatConstant, SootDoubleConstant, SootLongConstant,\
    SootStringConstant, SootNullConstant, SootClassConstant, SootLocal, SootArrayRef, SootInstanceFieldRef, SootStaticFieldRef
from ...infoflow.util.typeutils import TypeUtils

logger = logging.Logger(__file__)


def is_constant(obj):
    constants = [SootIntConstant, SootFloatConstant, SootDoubleConstant, SootLongConstant, SootStringConstant,
                 SootNullConstant, SootClassConstant]
    for constant in constants:
        if isinstance(obj, constant):
            return True

    return False


class Aliasing:

    def __init__(self, aliasing_strategy, manager):
        self.aliasing_strategy = aliasing_strategy
        self.implicit_flow_aliasing_strategy = ImplicitFlowAliasStrategy(manager)
        self.manager = manager
        self.excluded_from_must_alias_analysis = list()
        self.strong_alias_analysis = dict()

    def compute_aliases(self, d1, src, target_value, taint_set, method, new_abs):
        if not self.can_have_aliases(new_abs.getAccessPath()) and not self.is_string_constructor_call(src):
            return

        if len(d1.getAccessPath()) > 0:
            self.aliasing_strategy.compute_alias_taints(d1, src, target_value, taint_set, method, new_abs)
        elif isinstance(target_value, SootInstanceFieldRef):
            self.implicit_flow_aliasing_strategy.compute_alias_taints(d1, src, target_value, taint_set, method, new_abs)

    def get_referenced_ap_base(self, tainted_ap, referenced_fields):
        bases = self.manager.getAccessPathFactory().getBaseForType(
            tainted_ap.get_first_field_type()) if tainted_ap.isStaticFieldRef() \
            else self.manager.getAccessPathFactory().getBaseForType(tainted_ap.base_type)
        field_idx = 0

        while field_idx < len(referenced_fields):
            if field_idx >= tainted_ap.getFieldCount():
                if tainted_ap.getTaintSubFields():
                    return tainted_ap
                else:
                    return None

            if tainted_ap.fields[field_idx] != referenced_fields[field_idx]:
                if bases is not None and not (tainted_ap.isStaticFieldRef() and field_idx == 0):
                    for base in bases:
                        if base.fields[0] == referenced_fields[field_idx]:
                            cut_fields = tainted_ap.fields[:field_idx]
                            cut_fields.extends(base.fields[:len(base.fields)])
                            cut_fields.extends(tainted_ap.fields[field_idx:tainted_ap.getFieldCount()])

                            cut_field_types = tainted_ap.field_types[:field_idx]
                            cut_field_types.extends(base.types[:len(base.types)])
                            cut_field_types.extends(
                                tainted_ap.field_types[field_idx:tainted_ap.getFieldCount() - field_idx])

                            return self.manager.getAccessPathFactory().createAccessPath(tainted_ap.value,
                                                                                         cut_fields, tainted_ap.base_type,
                                                                                         cut_field_types,
                                                                                         tainted_ap.getTaintSubFields(),
                                                                                         False, False,
                                                                                         tainted_ap.getArrayTaintType())

                return None

            field_idx += 1

        return tainted_ap

    def may_alias(self, val1, val2):
        if isinstance(val1, AccessPath):
            ap = val1
            val = val2

            if not AccessPath.can_contain_value(val):
                return None

            if is_constant(val):
                return None

            if self.aliasing_strategy.isInteractive():
                if not self.aliasing_strategy.may_alias(ap, self.manager.getAccessPathFactory().createAccessPath(val, True)):
                    return None
            else:
                if isinstance(val, SootLocal):
                    if ap.value != val:
                        return None

                if isinstance(val, SootArrayRef):
                    if ap.value != val.base:
                        return None

                if isinstance(val, SootInstanceFieldRef):
                    if not ap.is_local() and not ap.is_instance_field_ref():
                        return None
                    if val.base != ap.value:
                        return None

            if isinstance(val, SootStaticFieldRef):
                if not ap.is_static_field_ref():
                    return None

            fields = val.field if isinstance(val, SootInstanceFieldRef) or isinstance(val, SootStaticFieldRef) else list()
            return self.get_referenced_ap_base(ap, fields)
        if not AccessPath.can_contain_value(val1) or not AccessPath.can_contain_value(val2):
            return False

        if is_constant(val1) or is_constant(val2):
            return False

        if val1 == val2:
            return True

        if self.aliasing_strategy.isInteractive():
            return self.aliasing_strategy.may_alias(self.manager.getAccessPathFactory().createAccessPath(val1, False),
                                                     self.manager.getAccessPathFactory().createAccessPath(val2, False))

        return False

    def must_alias(self, val1, val2, position=None):
        if position is None:
            return val1 == val2

        if val1 == val2:
            return True

        if not isinstance(val1.type, RefLikeType) or not isinstance(val2.type, RefLikeType):
            return False

        method = self.manager.icfg.getMethodOf(position)
        if method in self.excluded_from_must_alias_analysis:
            return False

        if self.manager.isAnalysisAborted():
            return False

        try:
            if method in self.strong_alias_analysis:
                self.strong_alias_analysis[method] = None     # dummy
                #self.strongAliasAnalysis[method] = StrongLocalMustAliasAnalysis(self.manager.icfg.getOrCreateUnitGraph(method))
            lmaa = method
            return lmaa.must_alias(val1, position, val2, position)
        except Exception as e:
            logger.error("Error in SootLocal must alias analysis" + str(e))
            return False

    def can_have_aliases(self, stmt, val=None, source=None):
        if isinstance(stmt, AccessPath):
            ap = stmt
            if TypeUtils(self.manager).is_string_type(ap.base_type) and not ap.can_have_immutable_aliases:
                return False

            if ap.is_static_field_ref():
                if isinstance(ap.get_first_field_type(), PrimType):
                    return False
            elif isinstance(ap.base_type, PrimType):
                return False

            return True

        if isinstance(stmt, DefinitionStmt):
            def_stmt = stmt
            if isinstance(def_stmt.left_op, SootLocal) and def_stmt.left_op == source.getAccessPath().value:
                return False

            if isinstance(val, SootArrayRef):
                return True
            if isinstance(val, SootInstanceFieldRef) or isinstance(val, SootStaticFieldRef):
                return True

        if isinstance(val, SootInstanceFieldRef):
            instance_field_ref = val
            base = instance_field_ref.base
            if isinstance(base.type, PrimType):
                return False
        elif isinstance(val, SootLocal):
            if isinstance(val.type, PrimType):
                return False

        if is_constant(val):
            return False

        if TypeUtils(self.manager).is_string_type(val.type) and not self.is_string_constructor_call(stmt) \
                and not source.getAccessPath().can_have_immutable_aliases:
            return False

        return isinstance(val, SootInstanceFieldRef) or isinstance(val, SootStaticFieldRef) \
               or (isinstance(val, SootLocal) and isinstance(val.type, ArrayType))

    def is_string_constructor_call(self, i_stmt):
        sc_string = Scene.v().getSootClassUnsafe("java.lang.String")
        callees = self.manager.icfg.getCalleesOfCallAt(i_stmt)
        if callees is not None and not callees.isEmpty():
            for callee in callees:
                if callee.getDeclaringClass() == sc_string and callee.isConstructor():
                    return True

        return False

    def base_matches(self, base_value, source):
        if isinstance(base_value, SootLocal):
            if base_value == source.getAccessPath().value:
                return True
        elif isinstance(base_value, SootInstanceFieldRef):
            ifr = base_value
            if ifr.base.equals(source.getAccessPath().value) and source.getAccessPath().firstFieldMatches(
                    ifr.field):
                return True
        elif isinstance(base_value, SootStaticFieldRef):
            sfr = base_value
            if source.getAccessPath().firstFieldMatches(sfr.field):
                return True

        return False

    def base_matches_strict(self, base_value, source):
        if not self.base_matches(base_value, source):
            return False

        if isinstance(base_value, SootLocal):
            return source.getAccessPath().isLocal()
        elif isinstance(base_value, SootInstanceFieldRef) or isinstance(base_value, SootStaticFieldRef):
            return source.getAccessPath().getFieldCount() == 1

        raise RuntimeError("Unexpected left side")

    def exclude_method_from_must_alias(self, method):
        self.excluded_from_must_alias_analysis.append(method)
