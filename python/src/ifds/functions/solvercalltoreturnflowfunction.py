import CastExpr, InstanceOfExpr, LengthExpr, NewArrayExpr, InstanceInvokeExpr
import Collections
import HashSet
import ByReferenceBoolean
import FlowFunctionType
from ..flowfunction import FlowFunction
from ..misc.copymember import copy_member


class SolverCallToReturnFlowFunction(FlowFunction):

    def __init__(self, flowfunctions, call, return_site):
        copy_member(self, flowfunctions)
        self.call = call
        self.return_site = return_site

    def compute_targets(self, d1, source):
        res = self.computeTargetsInternal(d1, source)
        return self.notify_out_flow_handlers(self.call, d1, source, res, FlowFunctionType.CallToReturnFlowFunction)

    def computeTargetsInternal(self, d1, source):
        if self.manager.getConfig().getStopAfterFirstFlow() and not self.results.isEmpty():
            return None

        if self.taint_propagation_handler is not None:
            self.taint_propagation_handler.notify_flow_in(self.call, source, self.manager,
                                                       FlowFunctionType.CallToReturnFlowFunction)

        new_source = None
        if not source.isAbstractionActive() \
                and self.call == source.getActivationUnit() \
                or self.is_call_site_activating_taint(self.call, source.getActivationUnit()):
            new_source = source.getActiveCopy()
        else:
            new_source = source

        killSource = ByReferenceBoolean()
        killAll = ByReferenceBoolean()
        res = self.propagation_rules.apply_call_to_return_flow_function( d1, new_source, self.i_call_stmt,
                                                                         killSource, killAll, True )
        if killAll.value:
            return None
        pass_on = not killSource.value

        if source == self.get_zero_value():
            return Collections.emptySet() if res is None or res.isEmpty() else res

        if res is None:
            res = HashSet()

        if new_source.getTopPostdominator() is not None \
                and new_source.getTopPostdominator().getUnit() is None:
            return Collections.singleton(new_source)

        if new_source.getAccessPath().isStaticFieldRef():
            pass_on = False

        if pass_on \
                and isinstance(self.invExpr, InstanceInvokeExpr) \
                and (self.manager.getConfig().getInspectSources() or not self.isSource) \
                and (self.manager.getConfig().getInspectSinks() or not self.isSink) \
                and new_source.getAccessPath().isInstanceFieldRef() \
                and (self.hasValidCallees \
                     or (self.taintWrapper is not None and self.taintWrapper.isExclusive(self.i_call_stmt, new_source))):

            callees = self.interprocedural_cfg().getCalleesOfCallAt(self.call)
            all_callees_read = not callees.isEmpty()
            for callee in callees:
                if callee.isConcrete() and callee.hasActiveBody():
                    callee_aps = self.mapAccessPathToCallee(callee, self.invExpr, None, None, source.getAccessPath())
                    if callee_aps is not None:
                        for ap in callee_aps:
                            if ap is not None:
                                if not self.interprocedural_cfg().methodReadsValue(callee, ap.getPlainValue()):
                                    all_callees_read = False
                                    break

                if self.is_excluded(callee):
                    all_callees_read = False
                    break

            if all_callees_read:
                if self.aliasing.mayAlias(self.invExpr.getBase(), new_source.getAccessPath().getPlainValue()):
                    pass_on = False
                if pass_on:
                    for i in range(self.call_args.length):
                        if self.aliasing.mayAlias(self.call_args[i], new_source.getAccessPath().getPlainValue()):
                            pass_on = False
                            break
                if new_source.getAccessPath().isStaticFieldRef():
                    pass_on = False

        if source.getAccessPath().isStaticFieldRef():
            if not self.interprocedural_cfg().isStaticFieldUsed(callee, source.getAccessPath().getFirstField()):
                pass_on = True

        pass_on |= source.getTopPostdominator() is not None or source.getAccessPath().isEmpty()
        if pass_on:
            if new_source != self.get_zero_value():
                res.add(new_source)

        if callee.isNative():
            for call_val in self.call_args:
                if call_val == new_source.getAccessPath().getPlainValue():
                    native_abs = self.nc_handler.getTaintedValues(self.i_call_stmt, new_source, self.call_args)
                    if native_abs is not None:
                        res.addAll(native_abs)

                        for abs in native_abs:
                            if abs.getAccessPath().isStaticFieldRef() \
                                    or self.aliasing.canHaveAliases(self.i_call_stmt,
                                                                abs.getAccessPath().getCompleteValue(),
                                                                abs):
                                self.aliasing.computeAliases(d1, self.i_call_stmt,
                                                         abs.getAccessPath().getPlainValue(), res,
                                                         self.interprocedural_cfg().get_method_of(self.call), abs)
                    break

        for abs in res:
            if abs != new_source:
                abs.setCorrespondingCallSite(self.i_call_stmt)

        return res