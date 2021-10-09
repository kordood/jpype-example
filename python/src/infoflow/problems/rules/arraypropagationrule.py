from .abstracttaintpropagationrule import AbstractTaintPropagationRule
from ...data.accesspath import ArrayTaintType
from ...sootir.soot_statement import AssignStmt
from ...sootir.soot_expr import SootLengthExpr, SootNewArrayExpr
from ...sootir.soot_value import SootArrayRef


class ArrayPropagationRule(AbstractTaintPropagationRule):

    def propagate_normal_flow(self, d1, source, stmt, dest_stmt, kill_source, kill_all):
        if not isinstance(stmt, AssignStmt):
            return None
        assign_stmt = stmt

        new_abs = None
        left_val = assign_stmt.left_op
        right_val = assign_stmt.right_op

        if isinstance(right_val, SootLengthExpr):
            length_expr = right_val
            if self.manager.aliasing.mayAlias(source.getAccessPath().getPlainValue(), length_expr.getOp()):
                if source.getAccessPath().getArrayTaintType() == ArrayTaintType.Contents:
                    return None

                ap = self.manager.getAccessPathFactory().createAccessPath(left_val, None, IntType.v(), None, True,
                                                                          False, True, ArrayTaintType.ContentsAndLength)
                new_abs = source.deriveNewAbstraction(ap, assign_stmt)

        elif isinstance(right_val, SootArrayRef):
            right_base = right_val.base
            right_index = right_val.index

            if source.getAccessPath().getArrayTaintType() != ArrayTaintType.Length \
                    and self.manager.aliasing.mayAlias(right_base, source.getAccessPath().getPlainValue()):
                target_type = source.getAccessPath().getBaseType()
                assert isinstance(target_type, ArrayType)
                target_type = target_type.getElementType()
                array_taint_type = source.getAccessPath().getArrayTaintType()
                ap = self.manager.getAccessPathFactory().copyWithNewValue(source.getAccessPath(), left_val, target_type,
                                                                          False, True, array_taint_type)
                new_abs = source.deriveNewAbstraction(ap, assign_stmt)

            elif source.getAccessPath().getArrayTaintType() != ArrayTaintType.Length \
                    and right_index == source.getAccessPath().getPlainValue() \
                    and self.manager.config.getImplicitFlowMode().trackArrayAccesses():
                array_taint_type = ArrayTaintType.ContentsAndLength
                ap = self.manager.getAccessPathFactory().copyWithNewValue(source.getAccessPath(), left_val, None, False,
                                                                          True, array_taint_type)
                new_abs = source.deriveNewAbstraction(ap, assign_stmt)

        elif isinstance(right_val, SootNewArrayExpr) and self.manager.config.getEnableArraySizeTainting():
            new_array_expr = right_val

            if self.manager.aliasing.mayAlias(source.getAccessPath().getPlainValue(), new_array_expr.size):
                ap = self.manager.getAccessPathFactory().copyWithNewValue(source.getAccessPath(), left_val, None, False,
                                                                          True, ArrayTaintType.Length)
                new_abs = source.deriveNewAbstraction(ap, assign_stmt)

        if new_abs is None:
            return None

        res = list()
        res.append(new_abs)

        if self.manager.aliasing.canHaveAliases(assign_stmt, left_val, new_abs):
            self.manager.aliasing.computeAliases(d1, assign_stmt, left_val, res,
                                                 self.manager.icfg.getMethodOf(assign_stmt), new_abs)

        return res

    def propagate_call_flow(self, d1, source, stmt, dest, kill_all):
        return None

    def propagate_call_to_return_flow(self, d1, source, stmt, kill_source, kill_all):
        return None

    def propagate_return_flow(self, caller_d1s, source, stmt, ret_site, call_site, kill_all):
        return None
