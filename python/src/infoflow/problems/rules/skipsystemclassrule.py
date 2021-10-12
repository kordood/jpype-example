from .abstracttaintpropagationrule import AbstractTaintPropagationRule
from ...sootir.soot_method import SootMethod


class SkipSystemClassRule(AbstractTaintPropagationRule):

    def __init__(self, manager, zero_value, results):
        super().__init__(manager, zero_value, results)
        for node in manager.icfg.nodes():
            if isinstance(node, int):
                continue

            if isinstance(node, SootMethod):
                fullname = node.class_name + '.' + node.name
            else:
                fullname = node.fullname

            if fullname == "java.lang.Object.<init>":
                self.object_cons = node
            elif fullname == "java.lang.Object.<clinit>":
                self.object_clinit = node
            elif fullname == "java.lang.Object.getclass":
                self.object_get_class = node
            elif fullname == "java.lang.Thread.<init>":
                self.thread_cons = node

    def propagate_normal_flow(self, d1, source, stmt, dest_stmt, kill_source, kill_all):
        return None

    def propagate_call_flow(self, d1, source, stmt, dest, kill_all):
        if self.is_system_class_dest(dest):
            kill_all.value = True

        return None

    def is_system_class_dest(self, dest):
        return dest == self.object_cons or dest == self.object_clinit or dest == self.object_get_class \
               or dest == self.thread_cons

    def propagate_call_to_return_flow(self, d1, source, stmt, kill_source, kill_all):
        callees = self.manager.icfg.getCalleesOfCallAt(stmt)
        if callees.isEmpty():
            return None

        for callee in self.manager.icfg.getCalleesOfCallAt(stmt):
            if not self.is_system_class_dest(callee):
                return None

        return list(source)

    def propagate_return_flow(self, caller_d1s, source, stmt, ret_site, call_site, kill_all):
        return None
