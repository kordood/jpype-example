#import ByReferenceBoolean
#import FlowFunctionType
from ..problems.flowfunction import FlowFunction
from ..problems.flowfunctions import FlowFunctions
from ..misc.copymember import copy_member


class SolverCallFlowFunction(FlowFunction):
    
    def __init__(self, flow_functions: FlowFunctions, src, dest):
        self.flow_functions = flow_functions
        self.manager = flow_functions.manager
        self.results = flow_functions.results
        self.src = src
        self.dest = dest

    def compute_targets(self, d1, source):
        res = self.compute_targets_internal(d1, source)
        if res is not None and not res.isEmpty() and d1 is not None:
            for abstraction in res:
                self.flow_functions.aliasing.getAliasingStrategy().injectCallingContext(abstraction, self.flow_functions.solver, self.dest, self.src, source,
                                                                         d1
                                                                        )
        return self.flow_functions.notify_out_flow_handlers(self.flow_functions.stmt, d1, source, res, FlowFunctionType.CallFlowFunction)

    def compute_targets_internal(self, d1, source):
        if self.flow_functions.manager.getConfig().getStopAfterFirstFlow() and not self.results.is_empty():
            return None
        if source == self.flow_functions.get_zero_value():
            return None

        if self.flow_functions.is_excluded(self.dest):
            return None

        if self.flow_functions.taint_propagation_handler is not None:
            self.taint_propagation_handler.notify_flow_in(self.stmt, source, self.manager,
                                                       FlowFunctionType.CallFlowFunction)

        if not source.is_abstraction_active() and source.getActivationUnit() == self.src:
            source = source.get_active_copy()

        kill_all = False
        res = self.propagation_rules.apply_call_flow_function(d1, source, self.stmt, self.dest, kill_all)
        if kill_all:
            return None

        res_mapping = self.map_access_path_to_callee(self.dest, self.ie,
                                                                    self.paramLocals,
                                                                    self.this_local,
                                                                    source.getAccessPath())
        if res_mapping is None:
            return res

        res_abs = HashSet(res_mapping.size())
        if res is not None and not res.is_empty():
            res_abs.add_all(res)
        for ap in res_mapping:
            if ap is not None:
                if self.aliasing.getAliasingStrategy().isLazyAnalysis() \
                        or source.isImplicit() \
                        or self.interprocedural_cfg().method_reads_value(self.dest, ap.getPlainValue()):
                    new_abs = source.deriveNewAbstraction(ap, self.stmt)
                    if new_abs is not None:
                        res_abs.add(new_abs)
        return res_abs
