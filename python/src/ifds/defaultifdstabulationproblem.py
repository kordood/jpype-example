from interproceduralcfg import InterproceduralCFG
from ifdstabulationproblem import IFDSTabulationProblem
import os


class DefaultIFDSTabulationProblem(InterproceduralCFG, IFDSTabulationProblem):

    def __init__(self, icfg):
        self.icfg = icfg
        self.flowFunctions = None
        self.zeroValue = None

    def createFlowFunctionsFactory(self):
        pass

    def createZeroValue(self):
        pass

    def flowFunctions(self):
        if self.flowFunctions is None:
            self.flowFunctions = self.createFlowFunctionsFactory()

        return self.flowFunctions

    def interproceduralCFG(self):
        return self.icfg

    def zeroValue(self):
        if self.zeroValue is None:
            self.zeroValue = self.createZeroValue()
        return self.zeroValue

    def followReturnsPastSeeds(self):
        return False
    
    def autoAddZero(self):
        return True

    def numThreads(self):
        return os.cpu_count()

    def computeValues(self):
        return True

    def recordEdges(self):
        return False
