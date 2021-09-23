from .abstractinfoflowproblem import AbstractInfoflowProblem
from .flowfunctions import FlowFunctions


class InfoflowProblem(AbstractInfoflowProblem):
    def __init__(self, manager, zero_value, rule_manager_factory):
        super(InfoflowProblem, self).__init__(manager)

        self.zero_value = self.create_zero_value() if zero_value is None else zero_value
        self.results = self.TaintPropagationResults(manager)
        self.propagation_rules = rule_manager_factory.createRuleManager(manager, self.zero_value, self.results)

    def create_flow_functions_factory(self):
        return FlowFunctions(self)

    def auto_add_zero(self):
        return False

    """
    Not using in python

    def get_results(self):
        return self.results
    def get_propagation_rules(self):
        return self.propagation_rules
    """
