from ...sootir.soot_statement import AssignStmt
from ...sootir.soot_value import SootInstanceFieldRef, SootStaticFieldRef
from ...sootir.soot_expr import SootVirtualInvokeExpr
"""import RefType
import Scene
"""
# import ExceptionalUnitGraph
# import JimpleBasedInterproceduralCFG

from ...misc.pyenum import PyEnum


class InfoflowCFG:
    MAX_SIDE_EFFECT_ANALYSIS_DEPTH = 25
    MAX_STATIC_USE_ANALYSIS_DEPTH = 50

    StaticFieldUse = PyEnum('Unknown', 'Unused', 'Read', 'Write', 'ReadWrite')

    def __init__(self, delegate):
        #(JimpleBasedInterproceduralCFG(True, True))
        self.delegate = delegate
        self.static_field_uses = dict()
        self.unit_to_postdominator = list()
        self.method_to_used_locals = list()
        self.method_to_written_locals = list()

    def get_postdominator_of(self, u):
        return self.unit_to_postdominator.append(u)

    def get_method_of(self, u):
        return self.delegate.get_method_of(u)

    def get_succs_of(self, u):
        return self.delegate.get_succs_of(u)

    def is_exit_stmt(self, u):
        return self.delegate.is_exit_stmt(u)

    def is_start_point(self, u):
        return self.delegate.is_start_point(u)

    def is_fall_through_successor(self, u, succ):
        return self.delegate.is_fall_through_successor(u, succ)

    def is_branch_target(self, u, succ):
        return self.delegate.is_branch_target(u, succ)

    def get_start_points_of(self, m):
        return self.delegate.get_start_points_of(m)

    def is_call_stmt(self, u):
        return self.delegate.is_call_stmt(u)

    def all_non_call_start_nodes(self):
        return self.delegate.all_non_call_start_nodes()

    def get_callees_of_call_at(self, u):
        return self.delegate.get_callees_of_call_at(u)

    def get_callers_of(self, m):
        return self.delegate.get_callers_of(m)

    def get_return_sites_of_call_at(self, u):
        return self.delegate.get_return_sites_of_call_at(u)

    def get_calls_from_within(self, m):
        return self.delegate.get_calls_from_within(m)

    def get_preds_of(self, u):
        return self.delegate.get_preds_of(u)

    def get_end_points_of(self, m):
        return self.delegate.get_end_points_of(m)

    def get_preds_of_call_at(self, u):
        return self.delegate.get_preds_of(u)

    def all_non_call_end_nodes(self):
        return self.delegate.all_non_call_end_nodes()

    def get_or_create_unit_graph(self, m):
        return self.delegate.get_or_create_unit_graph(m)

    def get_parameter_refs(self, m):
        return self.delegate.get_parameter_refs(m)

    def is_return_site(self, n):
        return self.delegate.is_return_site(n)

    def is_static_field_read(self, method, variable):
        use = self.check_static_field_used(method, variable)
        return use == self.StaticFieldUse.Read or use == self.StaticFieldUse.ReadWrite \
               or use == self.StaticFieldUse.Unknown

    def is_static_field_used(self, method, variable):
        use = self.check_static_field_used(method, variable)
        return use == self.StaticFieldUse.Write or use == self.StaticFieldUse.ReadWrite \
               or use == self.StaticFieldUse.Unknown

    def check_static_field_used(self, smethod, variable):
        if not smethod.is_concrete or not smethod.hasActiveBody():
            return self.StaticFieldUse.Unused

        work_list = list()
        work_list.append(smethod)
        temp_uses = dict()

        processed_methods = 0
        while len(work_list) > 0:
            method = work_list.pop(len(work_list) - 1)
            processed_methods += 1

            if not method.hasActiveBody():
                continue

            if processed_methods > self.MAX_STATIC_USE_ANALYSIS_DEPTH:
                return self.StaticFieldUse.Unknown

            has_invocation = False
            reads = False
            writes = False

            entry = self.static_field_uses.get(method)
            if entry is not None:
                b = entry.get(variable)
                if b is not None and b != self.StaticFieldUse.Unknown:
                    temp_uses[method] = b
                    continue

            old_use = temp_uses.get(method)

            for u in method.active_body.units:
                if isinstance(u, AssignStmt):
                    assign = u

                    if isinstance(assign.getLeftOp(), SootStaticFieldRef):
                        sf = assign.getLeftOp().getField()
                        self.register_static_variable_use(method, sf, self.StaticFieldUse.Write)
                        if variable == sf:
                            writes = True

                    if isinstance(assign.getRightOp(), SootStaticFieldRef):
                        sf = assign.getRightOp().getField()
                        self.register_static_variable_use(method, sf, self.StaticFieldUse.Read)
                        if variable == sf:
                            reads = True

                if u.containsInvokeExpr():
                    for edge in Scene.v().getCallGraph().edgesOutOf(u):
                        callee = edge.target.method
                        if callee.is_concrete:

                            callee_use = temp_uses.get(callee)
                            if callee_use is None:

                                if not has_invocation:
                                    work_list.append(method)

                                work_list.append(callee)
                                has_invocation = True
                            else:
                                reads |= callee_use == self.StaticFieldUse.Read or \
                                         callee_use == self.StaticFieldUse.ReadWrite
                                writes |= callee_use == self.StaticFieldUse.Write or \
                                          callee_use == self.StaticFieldUse.ReadWrite

            field_use = self.StaticFieldUse.Unused
            if reads and writes:
                field_use = self.StaticFieldUse.ReadWrite
            elif reads:
                field_use = self.StaticFieldUse.Read
            elif writes:
                field_use = self.StaticFieldUse.Write

            if field_use == old_use:
                continue
            temp_uses[method] = field_use

        for key, value in temp_uses.items():
            self.register_static_variable_use(key, variable, value)

        outer_use = temp_uses.get(smethod)
        return self.StaticFieldUse.Unknown if outer_use is None else outer_use

    def register_static_variable_use(self, method, variable, field_use):
        entry = self.static_field_uses.get(method)
        if entry is None:
            entry = dict()
            self.static_field_uses[method] = entry
            entry[variable] = field_use
            return

        old_use = entry.get(variable)
        if old_use is None:
            entry[variable] = field_use
            return

        new_use = None
        if old_use == self.StaticFieldUse.Unknown:
            pass
        elif old_use == self.StaticFieldUse.Unused:
            pass
        elif old_use == self.StaticFieldUse.ReadWrite:
            new_use = field_use
        elif old_use == self.StaticFieldUse.Read:
            new_use = old_use if (field_use == self.StaticFieldUse.Read) else self.StaticFieldUse.ReadWrite
        elif old_use == self.StaticFieldUse.Write:
            new_use = old_use if (field_use == self.StaticFieldUse.Write) else self.StaticFieldUse.ReadWrite
        else:
            raise RuntimeError("Invalid field use")
        entry[variable] = new_use

    def has_side_effects(self, method, run_list=None, depth=0):
        if run_list is None:
            run_list = list()

        if not method.hasActiveBody():
            return False

        if not run_list.add(method):
            return False

        has_side_effects = self.static_field_uses.get(method)
        if has_side_effects is not None:
            return has_side_effects

        if depth > self.MAX_SIDE_EFFECT_ANALYSIS_DEPTH:
            return True

        for u in method.active_body.units:
            if isinstance(u, AssignStmt):
                assign = u

                if isinstance(assign.getLeftOp(), SootInstanceFieldRef):
                    self.static_field_uses[method] = True
                    return True

            if u.containsInvokeExpr():
                for edge in Scene.v().getCallGraph().edgesOutOf(u):
                    depth += 1
                    if self.has_side_effects(edge.target.method, run_list, depth):
                        return True

        self.static_field_uses[method] = False
        return False

    """
    NOT YET
    def notifyMethodChanged(self, m):
        if isinstance(self.delegate, JimpleBasedInterproceduralCFG):
            self.delegate.initializeUnitToOwner(m)
    """

    def method_reads_value(self, m, v):
        self.method_to_used_locals.append(m)
        reads = m['value']
        if reads is not None:
            for local in reads:
                if local == v:
                    return True
        return False

    def method_writes_value(self, m, v):
        self.method_to_written_locals.append(m)
        writes = m['value']
        if writes is not None:
            for local in writes:
                if local == v:
                    return True
        return False

    def is_exceptional_edge_between(self, u1, u2):
        m1 = self.get_method_of(u1)
        m2 = self.get_method_of(u2)
        if m1 != m2:
            raise RuntimeError("Exceptional edges are only supported inside the same method")
        ug1 = self.get_or_create_unit_graph(m1)

        """
        NOT YET
        if not isinstance(ug1, ExceptionalUnitGraph):
            return False
        """

        eug = ug1
        if not eug.getExceptionalSuccsOf(u1).contains(u2):
            return False

        dests = eug.getExceptionDests(u1)
        if dests is not None and not dests.is_empty():
            ts = Scene.v().getDefaultThrowAnalysis().mightThrow(u1)
            if ts is not None:
                has_traps = False
                for dest in dests:
                    trap = dest.getTrap()
                    if trap is not None:
                        has_traps = True
                        if not ts.catchableAs(trap.getException().type):
                            return False

                if not has_traps:
                    return False
        return True

    def is_reachable(self, u):
        return self.delegate.is_reachable(u)

    @staticmethod
    def is_executor_execute(ie, dest):
        if ie is None or dest is None:
            return False

        ie_method = ie.getMethod()
        if not ie_method.name == "execute" and not ie_method.name == "doPrivileged":
            return False

        ie_sub_sig = ie_method.getSubSignature()
        callee_sub_sig = dest.getSubSignature()

        if ie_sub_sig == "execute(java.lang.Runnable)" and callee_sub_sig == "run()":
            return True

        if dest.name == "run" and dest.getParameterCount() == 0 and isinstance(dest.getReturnType(), RefType):
            if ie_sub_sig == "java.lang.Object doPrivileged(java.security.PrivilegedAction)":
                return True
            if ie_sub_sig == "java.lang.Object doPrivileged(java.security.PrivilegedAction,"\
                    + "java.security.AccessControlContext)":
                return True
            if ie_sub_sig == "java.lang.Object doPrivileged(java.security.PrivilegedExceptionAction)":
                return True
            if ie_sub_sig == "java.lang.Object doPrivileged(java.security.PrivilegedExceptionAction,"\
                    + "java.security.AccessControlContext)":
                return True
        return False

    def get_ordinary_callees_of_call_at(self, u):
        iexpr = u.getInvokeExpr()
        original_callees = self.get_callees_of_call_at(u)
        callees = list()
        for sm in original_callees:
            if not sm.isStaticInitializer() and not self.is_executor_execute(iexpr, sm):
                callees.append(sm)
        return callees

    def is_reflective_call_site(self, u, iexpr=None):
        if iexpr is None:
            if self.is_call_stmt(u):
                iexpr = u.getInvokeExpr()
                return self.is_reflective_call_site(iexpr)
            return False
        else:
            if isinstance(iexpr, SootVirtualInvokeExpr):
                viexpr = iexpr
                if isinstance(viexpr.base.type, RefType):
                    if (viexpr.base.type).getSootClass().name == "java.lang.reflect.Method":
                        if viexpr.getMethod().name == "invoke":
                            return True
            return False

    def purge(self):
        self.static_field_uses.clear()
        self.method_to_used_locals.clear()
        self.method_to_written_locals.clear()
        self.unit_to_postdominator.clear()
