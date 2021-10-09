from .propagationrulemanager import PropagationRuleManager


class DefaultPropagationRuleManagerFactory:

    def create_rule_manager(self, manager, zero_value, results):
        return PropagationRuleManager(manager, zero_value, results)
