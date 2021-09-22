import InstanceInvokeExpr
import DefinitionStmt
import TypeUtils, PrimType
import Aliasing
import HashSet
import ByReferenceBoolean
import FlowFunctionType
import AccessPath
from ..problems.flowfunction import FlowFunction
from ..misc.copymember import copy_member


class SolverReturnFlowFunction(FlowFunction):

    def __init__(self, flowfunctions, call_site, callee, exit_stmt, retSite):
        copy_member(self, flowfunctions)
        self.call_site = call_site
        self.callee = callee
        self.exit_stmt = exit_stmt
        self.retSite = retSite

    def compute_targets(self, source, d1, caller_d1s=None):
        res = self.compute_targets_internal(source, caller_d1s)
        return self.notify_out_flow_handlers(self.exit_stmt, d1, source, res, FlowFunctionType.ReturnFlowFunction)

    def compute_targets_internal(self, source, caller_d1s):
        if self.manager.getConfig().getStopAfterFirstFlow() and not self.results.is_empty():
            return None
        if source == self.get_zero_value():
            return None

        if self.taint_propagation_handler is not None:
            self.taint_propagation_handler.notify_flow_in(self.exit_stmt, source, self.manager,
                                                       FlowFunctionType.ReturnFlowFunction)
        caller_d1s_conditional = False
        for d1 in caller_d1s:
            if d1.getAccessPath().is_empty():
                caller_d1s_conditional = True
                break
        new_source = source
        if not source.is_abstraction_active():
            if self.call_site is not None:
                if self.call_site == source.getActivationUnit() \
                        or self.is_call_site_activating_taint(self.call_site, source.getActivationUnit()):
                    new_source = source.get_active_copy()

        if not new_source.isAbstractionActive() and new_source.getActivationUnit() is not None:
            if self.interprocedural_cfg().get_method_of(new_source.getActivationUnit()) == self.callee:
                return None

        kill_all = ByReferenceBoolean()
        res = self.propagation_rules.apply_return_flow_function(caller_d1s, new_source, self.exit_stmt, self.retSite,
                                                                 self.call_site, kill_all)
        if kill_all.value:
            return None
        if res is None:
            res = HashSet()

        if self.call_site is None:
            return None

        if self.aliasing.getAliasingStrategy().isLazyAnalysis() \
                and Aliasing.canHaveAliases(new_source.getAccessPath()):
            res.add(new_source)

        if not new_source.getAccessPath().is_static_field_ref() and not self.callee.isStaticInitializer():
            if self.return_stmt is not None and isinstance(self.call_site, DefinitionStmt):
                ret_local = self.return_stmt.getOp()
                defn_stmt = self.call_site
                left_op = defn_stmt.getLeftOp()

                if self.aliasing.mayAlias(ret_local, new_source.getAccessPath().getPlainValue()) \
                        and not self.isExceptionHandler(self.retSite):
                    ap = self.manager.getAccessPathFactory().copy_with_new_value(new_source.getAccessPath(), left_op)
                    abstraction = new_source.deriveNewAbstraction(ap, self.exit_stmt)
                    if abstraction is not None:
                        res.add(abstraction)
                        if self.aliasing.getAliasingStrategy().requiresAnalysisOnReturn():
                            for d1 in caller_d1s:
                                self.aliasing.computeAliases(d1, self.i_call_stmt, left_op, res,
                                                              self.interprocedural_cfg().get_method_of(self.call_site),
                                                              abstraction)

            source_base = new_source.getAccessPath().getPlainValue()
            parameter_aliases = False
            original_call_arg = None
            for i in range(self.callee.getParameterCount()):
                if isinstance(self.call_site, DefinitionStmt) and not self.isExceptionHandler(self.retSite):
                    defn_stmt = self.call_site
                    left_op = defn_stmt.getLeftOp()
                    original_call_arg = defn_stmt.getInvokeExpr().getArg(i)
                    if original_call_arg == left_op:
                        continue

                if self.aliasing.mayAlias(self.paramLocals[i], source_base):
                    parameter_aliases = True
                    original_call_arg = self.i_call_stmt.getInvokeExpr().getArg(1 if self.is_reflective_call_site else i)

                    if not AccessPath.can_contain_value(original_call_arg):
                        continue
                    if not self.is_reflective_call_site \
                            and not self.manager.getTypeUtils().check_cast(source.getAccessPath(),
                                                                            original_call_arg.type):
                        continue

                    if isinstance(source.getAccessPath().getBaseType(), PrimType):
                        continue
                    if TypeUtils.is_string_type(source.getAccessPath().getBaseType()) \
                            and not source.getAccessPath().getCanHaveImmutableAliases():
                        continue

                    if not source.getAccessPath().getTaintSubFields():
                        continue

                    if self.interprocedural_cfg().method_writes_value(self.callee, self.paramLocals[i]):
                        continue

                    ap = self.manager.getAccessPathFactory().copy_with_new_value(
                        new_source.getAccessPath(), original_call_arg,
                        None if self.is_reflective_call_site else new_source.getAccessPath().getBaseType(),
                        False)
                    abstraction = new_source.deriveNewAbstraction(ap, self.exit_stmt)

                    if abstraction is not None:
                        res.add(abstraction)

            this_aliases = False
            if isinstance(self.call_site, DefinitionStmt) and not self.isExceptionHandler(self.retSite):
                defn_stmt = self.call_site
                left_op = defn_stmt.getLeftOp()
                if self.this_local == left_op:
                    this_aliases = True

            if not parameter_aliases and not this_aliases and source.getAccessPath().getTaintSubFields() \
                    and isinstance(self.i_call_stmt.getInvokeExpr(), InstanceInvokeExpr) \
                    and self.aliasing.mayAlias(self.this_local, source_base):

                if self.manager.getTypeUtils().check_cast(source.getAccessPath(), self.this_local.type):
                    i_i_expr = self.i_call_stmt.getInvokeExpr()

                    caller_base_local = i_i_expr.getArg(0) \
                        if self.interprocedural_cfg().is_reflective_call_site(i_i_expr) else i_i_expr.base
                    ap = self.manager.getAccessPathFactory().copy_with_new_value(
                        new_source.getAccessPath(), caller_base_local,
                        None if self.is_reflective_call_site else new_source.getAccessPath().getBaseType(),
                        False)
                    abstraction = new_source.deriveNewAbstraction(ap, self.exit_stmt)
                    if abstraction is not None:
                        res.add(abstraction)

        for abstraction in res:
            if abstraction.isImplicit() and not caller_d1s_conditional \
                    or self.aliasing.getAliasingStrategy().requiresAnalysisOnReturn():
                for d1 in caller_d1s:
                    self.aliasing.computeAliases(d1, self.i_call_stmt, None, res,
                                                  self.interprocedural_cfg().get_method_of(self.call_site), abstraction)

            if abstraction != new_source:
                abstraction.setCorrespondingCallSite(self.i_call_stmt)
        return res
