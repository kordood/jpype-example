from .abstracttaintpropagationrule import AbstractTaintPropagationRule


class StopAfterFirstKFlowsPropagationRule(AbstractTaintPropagationRule):

    def check_stop(self, kill_all):
        if self.manager.config.getStopAfterFirstKFlows() == len(self.results):
            kill_all.value = True

    def propagate_normal_flow(self, d1, source, stmt, dest_stmt, kill_source, kill_all):
        self.check_stop(kill_all)
        return None

    def propagate_call_flow(self, d1, source, stmt, dest, kill_all):
        self.check_stop(kill_all)
        return None

    def propagate_call_to_return_flow(self, d1, source, stmt, kill_source, kill_all):
        self.check_stop(kill_all)
        return None

    def propagate_return_flow(self, caller_d1s, source, stmt, ret_site, call_site, kill_all):
        self.check_stop(kill_all)
        return None
    


