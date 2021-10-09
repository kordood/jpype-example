from .abstracttaintpropagationrule import AbstractTaintPropagationRule
from ...sootir.soot_statement import DefinitionStmt
from ...sootir.soot_expr import SootCastExpr


class TypingPropagationRule(AbstractTaintPropagationRule):

    def propagate_normal_flow(self, d1, source, stmt, dest_stmt, kill_source, kill_all):
        if not source.getAccessPath().isStaticFieldRef() and isinstance(stmt, DefinitionStmt):
            def_stmt = stmt

            if isinstance(def_stmt.right_op, SootCastExpr):
                ce = def_stmt.right_op

                if ce.getOp() == source.getAccessPath().getPlainValue():
                    if not self.manager.getTypeUtils().checkCast(source.getAccessPath(), ce.cast_type):
                        kill_all.value = True

        return None

    def propagate_call_flow(self, d1, source, stmt, dest, kill_all):
        return None

    def propagate_call_to_return_flow(self, d1, source, stmt, kill_source, kill_all):
        return None

    def propagate_return_flow(self, caller_d1s, source, stmt, ret_site, call_site, kill_all):
        return None
