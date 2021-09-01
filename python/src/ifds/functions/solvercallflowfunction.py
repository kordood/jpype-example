import HashSet
import ByReferenceBoolean
import FlowFunctionType
from ..flowfunction import FlowFunction


class SolverCallFlowFunction(FlowFunction):
    
    def __init__(self, flowfunctions):
        self.flowfunctions = flowfunctions

    def compute_targets(self, d1, source):
        res = self.compute_targets_internal(d1, source)
        if res is not None and not res.isEmpty() and d1 is not None:
            for abs in res:
                self.flowfunctions.aliasing.getAliasingStrategy().injectCallingContext(abs,
                                                                                       self.flowfunctions.solver,
                                                                                       self.flowfunctions.dest,
                                                                                       self.flowfunctions.src,
                                                                                       source,
                                                                                       d1
                                                                                       )
        return self.flowfunctions.infoflow.notify_out_flow_handlers(self.flowfunctions.stmt,
                                                        d1,
                                                        source,
                                                        res,
                                                        FlowFunctionType.CallFlowFunction
                                                        )

    def compute_targets_internal(self, d1, source):
        if self.flowfunctions.manager.getConfig().getStopAfterFirstFlow() and not self.flowfunctions.results.isEmpty():
            return None
        if source == self.flowfunctions.get_zero_value():
            return None

        if self.flowfunctions.isExcluded(self.flowfunctions.dest):
            return None

        if self.flowfunctions.taint_propagation_handler is not None:
            self.flowfunctions.taint_propagation_handler.notifyFlowIn(self.flowfunctions.stmt, source, self.flowfunctions.manager,
                                                       FlowFunctionType.CallFlowFunction)

        if not source.isAbstractionActive() and source.getActivationUnit() == self.flowfunctions.src:
            source = source.getActiveCopy()

        kill_all = ByReferenceBoolean()
        res = self.flowfunctions.propagation_rules.applyCallFlowFunction(d1, source, self.flowfunctions.stmt, self.flowfunctions.dest, kill_all)
        if kill_all.value:
            return None

        res_mapping = self.flowfunctions.mapAccessPathToCallee(self.flowfunctions.dest, self.flowfunctions.ie,
                                                               self.flowfunctions.paramLocals,
                                                               self.flowfunctions.thisLocal,
                                                               source.getAccessPath())
        if res_mapping is None:
            return res

        res_abs = HashSet(res_mapping.size())
        if res is not None and not res.isEmpty():
            res_abs.addAll(res)
        for ap in res_mapping:
            if ap is not None:
                if self.flowfunctions.aliasing.getAliasingStrategy().isLazyAnalysis() \
                        or source.isImplicit() \
                        or self.flowfunctions.interprocedural_cfg().methodReadsValue(self.flowfunctions.dest, ap.getPlainValue()):
                    new_abs = source.deriveNewAbstraction(ap, self.flowfunctions.stmt)
                    if new_abs is not None:
                        res_abs.add(new_abs)
        return res_abs
