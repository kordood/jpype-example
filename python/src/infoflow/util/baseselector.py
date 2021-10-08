from ..sootir.soot_expr import SootCastExpr, SootNewArrayExpr, SootInstanceOfExpr, SootUnopExpr, SootBinopExpr
from ..sootir.soot_value import SootArrayRef


class BaseSelector:

    def select_base(self, val, keep_array_ref):
        if isinstance(val, SootArrayRef) and not keep_array_ref:
            return val.getBase()
        elif isinstance(val, SootCastExpr):
            return val.getOp()
        elif isinstance(val, SootNewArrayExpr):
            return val.getSize()
        elif isinstance(val, SootInstanceOfExpr):
            return val.getOp()
        elif isinstance(val, SootUnopExpr):
            return val.getOp()
        return val

    def select_base_list(self, val, keep_array_ref):
        if isinstance(val, SootBinopExpr):
            base_list = list()
            expr = val
            base_list[0] = expr.getOp1()
            base_list[1] = expr.getOp2()
            return base_list

        else:
            return self.select_base(val, keep_array_ref) 
