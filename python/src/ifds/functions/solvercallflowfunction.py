import HashSet
import ByReferenceBoolean
import FlowFunctionType
from ..flowfunction import FlowFunction
from ..misc.copymember import copy_member


class SolverCallFlowFunction(FlowFunction):
    
    def __init__(self, flowfunctions):
        copy_member(self, flowfunctions)

    def compute_targets(self, d1, source):
        res = self.compute_targets_internal(d1, source)
        if res is not None and not res.isEmpty() and d1 is not None:
            for abs in res:
                self.aliasing.getAliasingStrategy().injectCallingContext(abs,
                                                                                       self.solver,
                                                                                       self.dest,
                                                                                       self.src,
                                                                                       source,
                                                                                       d1
                                                                                       )
        return self.notify_out_flow_handlers(self.stmt,
                                                        d1,
                                                        source,
                                                        res,
                                                        FlowFunctionType.CallFlowFunction
                                                        )

    def compute_targets_internal(self, d1, source):
        if self.manager.getConfig().getStopAfterFirstFlow() and not self.results.isEmpty():
            return None
        if source == self.get_zero_value():
            return None

        if self.isExcluded(self.dest):
            return None

        if self.taint_propagation_handler is not None:
            self.taint_propagation_handler.notifyFlowIn(self.stmt, source, self.manager,
                                                       FlowFunctionType.CallFlowFunction)

        if not source.isAbstractionActive() and source.getActivationUnit() == self.src:
            source = source.getActiveCopy()

        kill_all = ByReferenceBoolean()
        res = self.propagation_rules.applyCallFlowFunction(d1, source, self.stmt, self.dest, kill_all)
        if kill_all.value:
            return None

        res_mapping = self.map_access_path_to_callee( self.dest, self.ie,
                                                                    self.paramLocals,
                                                                    self.thisLocal,
                                                                    source.getAccessPath() )
        if res_mapping is None:
            return res

        res_abs = HashSet(res_mapping.size())
        if res is not None and not res.isEmpty():
            res_abs.addAll(res)
        for ap in res_mapping:
            if ap is not None:
                if self.aliasing.getAliasingStrategy().isLazyAnalysis() \
                        or source.isImplicit() \
                        or self.interprocedural_cfg().methodReadsValue(self.dest, ap.getPlainValue()):
                    new_abs = source.deriveNewAbstraction(ap, self.stmt)
                    if new_abs is not None:
                        res_abs.add(new_abs)
        return res_abs
