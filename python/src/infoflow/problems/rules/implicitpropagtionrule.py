from .abstracttaintpropagationrule import AbstractTaintPropagationRule
from ...data.abstractionatsink import AbstractionAtSink
from ...sootir.soot_statement import IfStmt, LookupSwitchStmt, TableSwitchStmt, DefinitionStmt
from ...sootir.soot_value import SootInstanceFieldRef, SootLocal, SootIntConstant, SootFloatConstant,\
    SootDoubleConstant, SootLongConstant, SootNullConstant, SootStringConstant, SootClassConstant


class ImplicitPropagtionRule(AbstractTaintPropagationRule):

    def __init__(self, manager, zero_value, results):
        super().__init__(manager, zero_value, results)
        self.implicit_targets = dict()

    def propagate_normal_flow(self, d1, source, stmt, dest_stmt, kill_source, kill_all):
        if source == self.zero_value:
            return None

        if self.leaves_conditional_branch( stmt, source, kill_all ):
            return None

        if not source.isAbstractionActive():
            return None

        if source.getAccessPath().isEmpty():
            return None

        values = list()
        if self.manager.getICFG().isExceptionalEdgeBetween(stmt, dest_stmt):
            for box in stmt.getUseBoxes():
                values.append(box.getValue())
        else:            
            if isinstance(stmt, IfStmt):
                condition = stmt.condition
            elif isinstance(stmt, LookupSwitchStmt):
                condition = stmt.key
            elif isinstance(stmt, TableSwitchStmt):
                condition = stmt.key
            else:
                return None

            if isinstance(condition, SootLocal):
                values.append(condition)
            else:
                for box in condition.getUseBoxes():
                    values.append(box.getValue())

        res = None
        for val in values:
            if self.manager.aliasing.may_alias( val, source.getAccessPath().getPlainValue() ):
                postdom = self.manager.getICFG().getPostdominatorOfstmt

                if not (postdom.getMethod() is None and source.getTopPostdominator() is not None
                        and self.manager.getICFG().getMethodOf(postdom.getUnit()) == source.getTopPostdominator().getMethod()):
                    new_abs = source.deriveConditionalAbstractionEnter(postdom, stmt)

                    if res is None:
                        res = list()
                    res.append(new_abs)
                    break

        return res

    def leaves_conditional_branch(self, stmt, source, kill_all):
        if source.isTopPostdominatorstmt:
            source = source.dropTopPostdominator()

            if source.getAccessPath().isEmpty() and source.getTopPostdominator() is None:
                if kill_all is not None:
                    kill_all.value = True
                return True

        return False

    def propagate_call_flow(self, d1, source, stmt, dest, kill_all):
        if source == self.zero_value:
            return None

        if self.leaves_conditional_branch( stmt, source, kill_all ):
            return None

        if stmt in self.implicit_targets.keys() and (d1 is None or d1 in self.implicit_targets[stmt]):
            if kill_all is not None:
                kill_all.value = True
            return None

        if source.getAccessPath().isEmpty():
            if d1 is not None:
                if self.implicit_targets.get(stmt) is None:
                    call_sites = list()
                    self.implicit_targets[stmt] = call_sites
                else:
                    call_sites = self.implicit_targets[stmt]

                call_sites.append(d1)

            abstraction = source.deriveConditionalAbstractionCallstmt
            return list(abstraction)

        elif source.getTopPostdominator() is not None:
            if kill_all is not None:
                kill_all.value = True
            return None

        return None

    def propagate_call_to_return_flow(self, d1, source, stmt, kill_source, kill_all):
        if source == self.zero_value:
            return None

        if self.leaves_conditional_branch( stmt, source, kill_all ):
            return None

        if source.isAbstractionActive():
            if source.getAccessPath().isEmpty() or source.getTopPostdominator() is not None:
                sink_info = self.manager.getSourceSinkManager().getSinkInfo(stmt, self.manager, None)
                if sink_info is not None:
                    self.results.addResult(AbstractionAtSink(sink_info.getDefinition(), source, stmt))
            else:
                cur_method = self.manager.getICFG().getMethodOfstmt
                if not cur_method.isStatic() and source.getAccessPath().getFirstField() is None \
                        and self.manager.aliasing.may_alias( cur_method.getActiveBody().getThisLocal(), source.getAccessPath().getPlainValue() ):
                    sink_info = self.manager.getSourceSinkManager().getSinkInfo(stmt, self.manager, None)
                    if sink_info is not None:
                        self.results.addResult(AbstractionAtSink(sink_info.getDefinition(), source, stmt))

        if isinstance(stmt, DefinitionStmt):
            implicit_taint = source.getTopPostdominator() is not None and source.getTopPostdominator().getUnit() is not None
            implicit_taint |= source.getAccessPath().isEmpty()

            if implicit_taint:
                left_val = stmt.left_op

                if (d1 is None or d1.getAccessPath().isEmpty()) and not isinstance(left_val, SootInstanceFieldRef):
                    return None

                abstraction = source.deriveNewAbstraction(self.manager.getAccessPathFactory().createAccessPath(left_val, True), stmt)
                return list(abstraction)

        return None

    def propagate_return_flow(self, caller_d1s, source, return_stmt, ret_site, call_site, kill_all):
        caller_d1s_conditional = False

        for d1 in caller_d1s:
            if d1.getAccessPath().isEmpty():
                caller_d1s_conditional = True
                break
            if isinstance(return_stmt, return_stmt) \
                    and isinstance(return_stmt.op, SootClassConstant) \
                    and isinstance(return_stmt.op, SootStringConstant) \
                    and isinstance(return_stmt.op, SootIntConstant) \
                    and isinstance(return_stmt.op, SootFloatConstant) \
                    and isinstance(return_stmt.op, SootLongConstant) \
                    and isinstance(return_stmt.op, SootDoubleConstant) \
                    and isinstance(return_stmt.op, SootNullConstant):
                if isinstance(call_site, DefinitionStmt):
                    define = call_site
                    ap = self.manager.getAccessPathFactory().copyWithNewValue(source.getAccessPath(), define.left_op)
                    abstraction = source.deriveNewAbstraction(ap, return_stmt)
                    res = list()
                    res.append(abstraction)

                    if self.manager.aliasing.can_have_aliases( define, define.left_op, abstraction ) \
                            and not caller_d1s_conditional:
                        for d1 in caller_d1s:
                            self.manager.aliasing.compute_aliases( d1, return_stmt, define.left_op, res, self.manager.getICFG().getMethodOf( call_site ), abstraction )
                        return res

        if source.getAccessPath().isEmpty():

            kill_all.value = True
            return None

        if isinstance(return_stmt, return_stmt) and isinstance(call_site, DefinitionStmt):
            defn_stmt = call_site
            left_op = defn_stmt.left_op
            inside_conditional = source.getTopPostdominator() is not None or source.getAccessPath().isEmpty()

            if inside_conditional and isinstance(left_op, SootInstanceFieldRef):
                ap = self.manager.getAccessPathFactory().copyWithNewValue(source.getAccessPath(), left_op)
                abstraction = source.deriveNewAbstraction(ap, return_stmt)

                if abstraction.isImplicit() and abstraction.getAccessPath().isFieldRef() and not caller_d1s_conditional:
                    res = list()
                    res.append(abstraction)

        return None
