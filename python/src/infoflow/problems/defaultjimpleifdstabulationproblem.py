from ..cfg.interproceduralcfg import InterproceduralCFG
from defaultifdstabulationproblem import DefaultIFDSTabulationProblem


class DefaultJimpleIFDSTabulationProblem(InterproceduralCFG, DefaultIFDSTabulationProblem):
    def __init__(self, icfg):
        super(icfg)