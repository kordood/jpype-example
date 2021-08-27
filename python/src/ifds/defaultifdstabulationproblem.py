from interproceduralcfg import InterproceduralCFG
from ifdstabulationproblem import IFDSTabulationProblem
import os


class DefaultIFDSTabulationProblem(InterproceduralCFG, IFDSTabulationProblem):

    def __init__(self, icfg):
        self.icfg = icfg
        self.flow_functions = None
        self.zero_value = None

    def create_flow_functions_factory(self):
        pass

    def create_zero_value(self):
        pass

    def flow_functions(self):
        if self.flow_functions is None:
            self.flow_functions = self.create_flow_functions_factory()

        return self.flow_functions

    def interprocedural_cfg(self):
        return self.icfg

    def zero_value(self):
        if self.zero_value is None:
            self.zero_value = self.create_zero_value()
        return self.zero_value

    def follow_returns_past_seeds(self):
        return False
    
    def auto_add_zero(self):
        return True

    def num_threads(self):
        return os.cpu_count()

    def compute_values(self):
        return True

    def record_edges(self):
        return False
