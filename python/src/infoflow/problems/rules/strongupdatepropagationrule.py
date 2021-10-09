from .abstracttaintpropagationrule import AbstractTaintPropagationRule
from ...sootir.soot_statement import AssignStmt
from ...sootir.soot_value import SootArrayRef, SootInstanceFieldRef, SootStaticFieldRef, SootLocal


class StrongUpdatePropagationRule(AbstractTaintPropagationRule):

    def propagate_normal_flow(self, d1, source, stmt, dest_stmt, kill_source, kill_all):
        if not isinstance(stmt, AssignStmt):
            return None

        assign_stmt = stmt

        if isinstance(assign_stmt.left_op, SootArrayRef):
            return None

        if not source.isAbstractionActive() and source.getCurrentStmt() == stmt:
            return None

        if source.getPredecessor() is not None and not source.getPredecessor().isAbstractionActive() \
                and source.isAbstractionActive() and source.getPredecessor().getActivationUnit() == stmt \
                and source.getAccessPath().equals(source.getPredecessor().getAccessPath()):
            return None

        if source.getAccessPath().isInstanceFieldRef():
            if isinstance(assign_stmt.left_op, SootInstanceFieldRef):
                left_ref = assign_stmt.left_op

                if source.isAbstractionActive():
                    base_aliases = self.manager.aliasing.mustAlias(left_ref.base, source.getAccessPath().getPlainValue(), assign_stmt)
                else:
                    base_aliases = left_ref.base == source.getAccessPath().getPlainValue()

                if base_aliases:
                    if self.manager.aliasing.mustAlias(left_ref.field, source.getAccessPath().getFirstField()):
                        kill_all.value = True
                        return None

            elif isinstance(assign_stmt.left_op, SootLocal):
                if self.manager.aliasing.mustAlias(assign_stmt.left_op, source.getAccessPath().getPlainValue(), stmt):
                    kill_all.value = True
                    return None

        elif source.getAccessPath().isStaticFieldRef():
            if isinstance(assign_stmt.left_op, SootStaticFieldRef) \
                    and self.manager.aliasing.mustAlias(assign_stmt.left_op.field, source.getAccessPath().getFirstField()):
                kill_all.value = True
                return None

        elif source.getAccessPath().isLocal() and isinstance(assign_stmt.left_op, SootLocal) \
                and assign_stmt.left_op == source.getAccessPath().getPlainValue():
            found = False

            for vb in assign_stmt.right_op.getUseBoxes():
                if vb.getValue() == source.getAccessPath().getPlainValue():
                    found = True
                    break

            kill_all.value = not found
            kill_source.value = True
            return None

        return None

    def propagate_call_flow(self, d1, source, stmt, dest, kill_all):
        return None

    def propagate_call_to_return_flow(self, d1, source, stmt, kill_source, kill_all):
        if isinstance(stmt, AssignStmt):
            ap = source.getAccessPath()

            if ap is not None:
                assign_stmt = stmt
                aliasing = self.manager.aliasing

                if aliasing is not None and not ap.isStaticFieldRef() and isinstance(assign_stmt.left_op, SootLocal) \
                        and aliasing.mayAlias(assign_stmt.left_op, ap.getPlainValue()):
                    kill_source.value = True

        return None

    def propagate_return_flow(self, caller_d1s, source, stmt, ret_site, call_site, kill_all):
        return None
