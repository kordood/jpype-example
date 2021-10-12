from .abstracttaintpropagationrule import AbstractTaintPropagationRule
from ...aliasing.aliasing import Aliasing
from ...infoflowconfiguration import StaticFieldTrackingMode
from ...util.typeutils import TypeUtils
from ...sootir.soot_expr import SootInvokeExpr
from ...sootir.soot_statement import DefinitionStmt


class WrapperPropagationRule(AbstractTaintPropagationRule):

    def propagate_normal_flow(self, d1, source, stmt, dest_stmt, kill_source, kill_all):
        return None

    def compute_wrapper_taints(self, d1, i_stmt, source):
        if source == self.zero_value:
            return None

        if self.manager.taint_wrapper is None:
            return None

        aliasing = self.manager.aliasing
        if aliasing is not None and not source.getAccessPath().isStaticFieldRef() and not source.getAccessPath().isEmpty():
            found = False

            if isinstance(i_stmt.getInvokeExpr(), SootInvokeExpr):
                ii_expr = i_stmt.getInvokeExpr()
                found = aliasing.may_alias( ii_expr.getBase(), source.getAccessPath().getPlainValue() )

            if not found:
                for paramIdx in range(0, i_stmt.getInvokeExpr().getArgCount()):
                    if aliasing.may_alias( source.getAccessPath().getPlainValue(), i_stmt.getInvokeExpr().getArg( paramIdx ) ):
                        found = True
                        break

            if not found:
                return None

        if not self.manager.config.getInspectSources():
            source_info = self.manager.getSourceSinkManager().getSourceInfo(i_stmt, self.manager) if self.manager.getSourceSinkManager() is not None else None
            if source_info is not None:
                return None

        res = self.manager.taint_wrapper.getTaintsForMethod(i_stmt, d1, source)

        if res is not None:
            res_with_aliases = res

            for abstraction in res:
                if not abstraction.equals(source):
                    self.check_and_propagate_alias( d1, i_stmt, res_with_aliases, abstraction )
            
            res = res_with_aliases

        return res

    def check_and_propagate_alias(self, d1, i_stmt, res_with_aliases, abstraction):
        val = abstraction.getAccessPath()
        is_basic_string = TypeUtils(self.manager).is_string_type(val.getBaseType()) and not val.getCanHaveImmutableAliases() and not self.manager.aliasing.is_string_constructor_call( i_stmt )
        taints_object_value = isinstance(val.getBaseType(), RefType) and isinstance(abstraction.getAccessPath().getBaseType(), RefType) and not is_basic_string
        taints_static_field = self.manager.config.getStaticFieldTrackingMode() != StaticFieldTrackingMode._None and abstraction.getAccessPath().isStaticFieldRef()
        tainted_value_overwritten = Aliasing.base_matches( i_stmt.left_op, abstraction ) if isinstance( i_stmt, DefinitionStmt ) else False

        if not tainted_value_overwritten:
            if taints_static_field or (taints_object_value and abstraction.getAccessPath().getTaintSubFields()) or self.manager.aliasing.can_have_aliases( i_stmt, val.getCompleteValue(), abstraction ):
                self.manager.aliasing.compute_aliases( d1, i_stmt, val.getPlainValue(), res_with_aliases, self.manager.icfg.getMethodOf( i_stmt ), abstraction )

    def propagate_call_to_return_flow(self, d1, source, stmt, kill_source, kill_all):
        wrapper_taints = self.compute_wrapper_taints( d1, stmt, source )
        if wrapper_taints is not None:
            for wrapper_abs in wrapper_taints:
                if wrapper_abs.getAccessPath().equals(source.getAccessPath()):
                    if wrapper_abs != source:
                        kill_source.value = True
                    break

        return wrapper_taints

    def propagate_return_flow(self, caller_d1s, source, stmt, ret_site, call_site, kill_all):
        return None

    def propagate_call_flow(self, d1, source, stmt, dest, kill_all):
        if self.manager.taint_wrapper is not None and self.manager.taint_wrapper.isExclusive(stmt, source):
            kill_all.value = True
        
        return None
