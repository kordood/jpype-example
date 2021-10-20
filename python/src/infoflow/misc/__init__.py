from pysoot.sootir.soot_statement import AssignStmt, InvokeStmt
from pysoot.sootir.soot_expr import SootInvokeExpr


def contains_invoke_expr(statement):
    if isinstance(statement, InvokeStmt):
        return True

    if isinstance(statement, AssignStmt):
        expr = statement.right_op
        if isinstance(expr, SootInvokeExpr):
            return True

    return False


def get_invoke_expr(statement):
    if isinstance(statement, InvokeStmt):
        return statement.invoke_expr
    elif isinstance(statement, AssignStmt):
        return statement.right_op


def find_method_by_expr(expr, nodes):
    fullname = expr.class_name + '.' + expr.method_name
    params = expr.method_params
    ret = expr.type

    for node in nodes:
        if node.fullname == fullname and node.parms == params and node.ret == ret:
            return node

    return None


def get_sub_signature(method):
    params = str(method.params).replace(',)', ')')
    sub_signature = method.ret + ' ' + method.name + params
    return sub_signature


def get_callees_of_call_at(statement, cfg):
    expr = get_invoke_expr(statement)
    methods = [find_method_by_expr(expr, cfg)]
    return methods



