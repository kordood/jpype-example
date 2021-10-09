from .abstracttaintpropagationrule import AbstractTaintPropagationRule
from ...sootir.soot_statement import DefinitionStmt, ThrowStmt
from ...sootir.soot_value import SootCaughtExceptionRef


class ExceptionPropagationRule(AbstractTaintPropagationRule):

    def propagate_normal_flow(self, d1, source, stmt, dest_stmt, kill_source, kill_all):
        if source == self.zero_value:
            return None

        if source.getExceptionThrown() and isinstance(stmt, DefinitionStmt):
            define = stmt
            if isinstance(define.right_op, SootCaughtExceptionRef):
                kill_source.value = True
                ap = self.manager.getAccessPathFactory().copyWithNewValue(source.getAccessPath(),
                        define.left_op)
                return None if ap is None else list(source.deriveNewAbstractionOnCatch(ap))

        if isinstance(stmt, ThrowStmt):
            throw_stmt = stmt
            if self.manager.aliasing.mayAlias(throw_stmt.getOp(), source.getAccessPath().getPlainValue()):
                kill_source.value = True
                return list(source.deriveNewAbstractionOnThrow(throw_stmt))

        return None

    def propagate_call_to_return_flow(self, d1, source, stmt, kill_source, kill_all):
        return None

    def propagate_return_flow(self, caller_d1s, source, stmt, ret_site, call_site, kill_all):
        if isinstance(stmt, ThrowStmt) and isinstance(ret_site, DefinitionStmt):
            def_ret_stmt = ret_site
            if isinstance(def_ret_stmt.right_op, SootCaughtExceptionRef):
                throw_stmt = stmt
                if self.manager.aliasing.mayAlias(throw_stmt.getOp(), source.getAccessPath().getPlainValue()):
                    return list(source.deriveNewAbstractionOnThrow(throw_stmt))

        return None

    def propagate_call_flow(self, d1, source, stmt, dest, kill_all):
        return None
