from ..sootir.soot_statement import AssignStmt
from ..sootir.soot_value import SootInstanceFieldRef, SootStaticFieldRef, SootLocal


class ImplicitFlowAliasStrategy:

    def __init__(self, manager):
        self.manager = manager
        self.solver = None
        self.method_to_aliases = dict()

    def _add_method_to_aliases(self, method):
        key = method
        value = self.compute_global_aliases( method )
        return value

    def compute_global_aliases(self, method):
        res = dict()

        for u in method.getActiveBody().getUnits():
            if not isinstance(u, AssignStmt):
                continue
            assign = u

            if not ((isinstance(assign.left_op, SootInstanceFieldRef) or isinstance(assign.left_op, SootStaticFieldRef)) 
                    and ((isinstance(assign.right_op, SootInstanceFieldRef) or isinstance(assign.right_op, SootStaticFieldRef)) 
                         or isinstance(assign.right_op, SootLocal))):
                if not ((isinstance(assign.right_op, SootInstanceFieldRef) or isinstance(assign.right_op, SootStaticFieldRef))
                        and ((isinstance(assign.left_op, SootInstanceFieldRef) or isinstance(assign.left_op, SootStaticFieldRef))
                             or isinstance(assign.left_op, SootLocal))):
                    continue

            ap_left = self.manager.getAccessPathFactory().createAccessPath(assign.left_op, True)
            ap_right = self.manager.getAccessPathFactory().createAccessPath(assign.right_op, True)

            map_left = res.get(ap_left)
            if map_left is None:
                map_left = list()
                res[ap_left] = map_left

            map_left.append(ap_right)

            map_right = res.get(ap_right)
            if map_right is None:
                map_right = list()
                res[ap_right] = map_right

            map_right.append(ap_left)

        return res

    def compute_alias_taints(self, d1, src, target_value, taint_set, method, new_abs):
        base_value = target_value.getBase()
        aliases = self._add_method_to_aliases(self.manager.getAccessPathFactory().createAccessPath(base_value, True))
        if aliases is not None:
            for ap in aliases:
                new_ap = self.manager.getAccessPathFactory().merge( ap, new_abs.getAccessPath() )
                alias_abs = new_abs.deriveNewAbstraction( new_ap, None )
                if taint_set.append( alias_abs ):
                    if ap.isInstanceFieldRef():
                        alias_base_val = Jimple.v().newInstanceFieldRef(ap.getPlainValue(), ap.getFirstField().makeRef())
                        self.compute_alias_taints( d1, src, alias_base_val, taint_set, method, alias_abs )

    def inject_calling_context(self, abstraction, f_solver, callee, call_site, source, d1):
        pass

    def is_flow_sensitive(self):
        return False

    def requires_analysis_on_return(self):
        return True

    def has_processed_method(self, method):
        if method in self.method_to_aliases:
            return method
        else:
            return None

    def cleanup(self):
        self.method_to_aliases = list()
