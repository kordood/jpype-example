from .abstracttaintpropagationrule import AbstractTaintPropagationRule


class SkipSystemClassRule(AbstractTaintPropagationRule):

    def __init__(self, manager, zero_value, results):
        super().__init__(manager, zero_value, results)
        self.object_cons = Scene.v().getObjectType().getSootClass().getMethodUnsafe( "void <init>()" )
        self.object_clinit = Scene.v().getObjectType().getSootClass().getMethodUnsafe( "void <clinit>()" )
        self.object_get_class = Scene.v().getObjectType().getSootClass().getMethodUnsafe( "java.lang.Class getClass()" )
        self.thread_cons = Scene.v().grabMethod( "<java.lang.Thread: void <init>()>" )

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
        callees = self.manager.getICFG().getCalleesOfCallAt(stmt)
        if callees.isEmpty():
            return None

        for callee in self.manager.getICFG().getCalleesOfCallAt(stmt):
            if not self.is_system_class_dest(callee):
                return None

        return list(source)

    def propagate_return_flow(self, caller_d1s, source, stmt, ret_site, call_site, kill_all):
        return None
