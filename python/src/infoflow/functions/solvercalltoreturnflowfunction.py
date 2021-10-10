
#import FlowFunctionType

from ..sootir.soot_expr import SootInvokeExpr
from ..problems.flowfunction import FlowFunction
#from ..problems.flowfunctions import FlowFunctions
from ..misc.copymember import copy_member


class SolverCallToReturnFlowFunction(FlowFunction):

    def __init__(self, flowfunctions, call, return_site):
        self.flowfunctions = flowfunctions
        self.call = call
        self.return_site = return_site

    def compute_targets(self, d1, source):
        res = self.compute_targets_internal( d1, source )
        return self.notify_out_flow_handlers(self.call, d1, source, res, FlowFunctionType.CallToReturnFlowFunction)

    def compute_targets_internal(self, d1, source):
        if self.flowfunctions.manager.getConfig().getStopAfterFirstFlow() and not self.flowfunctions.results.is_empty():
            return None

        if self.taint_propagation_handler is not None:
            self.taint_propagation_handler.notify_flow_in(self.call, source, self.flowfunctions.manager,
                                                       FlowFunctionType.CallToReturnFlowFunction)

        new_source = None
        if not source.is_abstraction_active() \
                and self.call == source.getActivationUnit() \
                or self.is_call_site_activating_taint(self.call, source.getActivationUnit()):
            new_source = source.get_active_copy()
        else:
            new_source = source

        killSource = False
        killAll = False
        res = self.propagation_rules.apply_call_to_return_flow_function(d1, new_source, self.i_call_stmt,
                                                                         killSource, killAll, True)
        if killAll:
            return None
        pass_on = not killSource

        if source == self.flowfunctions.get_zero_value():
            return list() if res is None or res.is_empty() else res

        if res is None:
            res = list()

        if new_source.getTopPostdominator() is not None \
                and new_source.getTopPostdominator().getUnit() is None:
            return set(new_source)

        if new_source.getAccessPath().is_static_field_ref():
            pass_on = False

        if pass_on \
                and isinstance(self.invExpr, SootInvokeExpr) \
                and (self.flowfunctions.manager.getConfig().getInspectSources() or not self.isSource) \
                and (self.flowfunctions.manager.getConfig().getInspectSinks() or not self.isSink) \
                and new_source.getAccessPath().is_instance_field_ref() \
                and (self.hasValidCallees \
                     or (self.taintWrapper is not None and self.taintWrapper.is_exclusive(self.i_call_stmt, new_source))):

            callees = self.flowfunctions.interprocedural_cfg().get_callees_of_call_at(self.call)
            all_callees_read = not callees.is_empty()
            for callee in callees:
                if callee.isConcrete() and callee.hasActiveBody():
                    callee_aps = self.mapAccessPathToCallee(callee, self.invExpr, None, None, source.getAccessPath())
                    if callee_aps is not None:
                        for ap in callee_aps:
                            if ap is not None:
                                if not self.interprocedural_cfg().method_reads_value(callee, ap.getPlainValue()):
                                    all_callees_read = False
                                    break

                if self.is_excluded(callee):
                    all_callees_read = False
                    break

            if all_callees_read:
                if self.aliasing.may_alias( self.invExpr.base, new_source.getAccessPath().getPlainValue() ):
                    pass_on = False
                if pass_on:
                    for i in range(self.call_args.length):
                        if self.aliasing.may_alias( self.call_args[i], new_source.getAccessPath().getPlainValue() ):
                            pass_on = False
                            break
                if new_source.getAccessPath().is_static_field_ref():
                    pass_on = False

        if source.getAccessPath().is_static_field_ref():
            if not self.interprocedural_cfg().is_static_field_used(callee, source.getAccessPath().get_first_field()):
                pass_on = True

        pass_on |= source.get_top_postdominator() is not None or source.getAccessPath().is_empty()
        if pass_on:
            if new_source != self.get_zero_value():
                res.add(new_source)

        if callee.isNative():
            for call_val in self.call_args:
                if call_val == new_source.getAccessPath().getPlainValue():
                    native_abs = self.nc_handler.getTaintedValues(self.i_call_stmt, new_source, self.call_args)
                    if native_abs is not None:
                        res.add_all(native_abs)

                        for abstraction in native_abs:
                            if abstraction.getAccessPath().is_static_field_ref() \
                                    or self.aliasing.can_have_aliases( self.i_call_stmt,
                                                                       abstraction.getAccessPath().get_complete_value(),
                                                                       abstraction ):
                                self.aliasing.compute_aliases( d1, self.i_call_stmt,
                                                               abstraction.getAccessPath().getPlainValue(), res,
                                                               self.interprocedural_cfg().get_method_of(self.call), abstraction )
                    break

        for abstraction in res:
            if abstraction != new_source:
                abstraction.setCorrespondingCallSite(self.i_call_stmt)

        return res