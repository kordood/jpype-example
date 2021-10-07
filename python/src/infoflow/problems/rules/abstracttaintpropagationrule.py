class AbstractTaintPropagationRule:

    def __init__(self, manager, zero_value, results):
        self.manager = manager
        self.zero_value = zero_value
        self.results = results
