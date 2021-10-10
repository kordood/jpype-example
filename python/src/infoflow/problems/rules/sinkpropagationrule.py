from .abstracttaintpropagationrule import AbstractTaintPropagationRule
from ...data.abstractionatsink import AbstractionAtSink
from ...sootir.soot_statement import ReturnStmt, IfStmt, LookupSwitchStmt, TableSwitchStmt, AssignStmt
from ...sootir.soot_expr import SootInvokeExpr
from ...util.baseselector import BaseSelector


class SinkPropagationRule(AbstractTaintPropagationRule):

    def __init__(self, manager, zero_value, results):
        super().__init__(manager, zero_value, results)
        self.kill_state = False

    def propagate_normal_flow(self, d1, source, stmt, dest_stmt, kill_source, kill_all):
        if isinstance(stmt, ReturnStmt):
            return_stmt = stmt
            self.check_for_sink(d1, source, stmt, return_stmt.getOp())
        elif isinstance(stmt, IfStmt):
            if_stmt = stmt
            self.check_for_sink(d1, source, stmt, if_stmt.getCondition())
        elif isinstance(stmt, LookupSwitchStmt):
            switch_stmt = stmt
            self.check_for_sink(d1, source, stmt, switch_stmt.getKey())
        elif isinstance(stmt, TableSwitchStmt):
            switch_stmt = stmt
            self.check_for_sink(d1, source, stmt, switch_stmt.getKey())
        elif isinstance(stmt, AssignStmt):
            assign_stmt = stmt
            self.check_for_sink(d1, source, stmt, assign_stmt.getRightOp())

        return None

    def check_for_sink(self, d1, source, stmt, ret_val):
        ap = source.getAccessPath()
        aliasing = self.manager.aliasing
        source_sink_manager = self.manager.getSourceSinkManager()

        if ap is not None and source_sink_manager is not None and aliasing is not None and source.isAbstractionActive():
            for val in BaseSelector().select_base_list(ret_val, False):
                if aliasing.may_alias( val, ap.getPlainValue() ):
                    sink_info = source_sink_manager.getSinkInfo(stmt, self.manager, source.getAccessPath())
                    if sink_info is not None:
                        if self.results.addResult(AbstractionAtSink(sink_info.getDefinition(), source, stmt)):
                            self.kill_state = True

    def propagate_call_flow(self, d1, source, stmt, dest, kill_all):
        if kill_all is not None:
            kill_all.value |= self.kill_state

        return None

    def is_taint_visible_in_callee(self, stmt, source):
        if self.manager.aliasing is None:
            return False

        iexpr = stmt.getInvokeExpr()
        found = False

        ap_base_value = source.getAccessPath().getPlainValue()
        if ap_base_value is not None:
            for i in range(0, iexpr.getArgCount()):
                if self.manager.aliasing.may_alias( iexpr.getArg( i ), ap_base_value ):
                    if source.getAccessPath().getTaintSubFields() or source.getAccessPath().isLocal():
                        return True

        if not found and isinstance(iexpr, SootInvokeExpr):
            if iexpr.getBase() == source.getAccessPath().getPlainValue():
                return True

        return False

    def propagate_call_to_return_flow(self, d1, source, stmt, kill_source, kill_all):
        if source.isAbstractionActive() and not source.getAccessPath().isStaticFieldRef():
            if not stmt.containsInvokeExpr() or self.is_taint_visible_in_callee(stmt, source):
                ssm = self.manager.getSourceSinkManager()

                if ssm is not None:
                    sinkInfo = ssm.getSinkInfo(stmt, self.manager, source.getAccessPath())

                    if sinkInfo is not None and not self.results.addResult(
                            AbstractionAtSink(sinkInfo.getDefinition(), source, stmt)):
                        self.kill_state = True

        if kill_all is not None:
            kill_all.value |= self.kill_state

        return None

    def propagate_return_flow(self, caller_d1s, source, stmt, ret_site, call_site, kill_all):
        if isinstance(stmt, ReturnStmt):
            return_stmt = stmt
            ssm = self.manager.getSourceSinkManager()
            aliasing = self.manager.aliasing

            matches = source.getAccessPath().isLocal() or source.getAccessPath().getTaintSubFields()

            if matches and source.isAbstractionActive() and ssm is not None and aliasing is not None \
                    and aliasing.may_alias( source.getAccessPath().getPlainValue(), return_stmt.getOp() ):
                sink_info = ssm.getSinkInfo(return_stmt, self.manager, source.getAccessPath())
                if sink_info is not None and not self.results.addResult(
                        AbstractionAtSink(sink_info.getDefinition(), source, return_stmt)):
                    self.kill_state = True

        if kill_all is not None:
            kill_all.value |= self.kill_state

        return None
