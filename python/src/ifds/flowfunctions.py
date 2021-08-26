class FlowFunctions:

    def getNormalFlowFunction(self, curr, succ):
        pass

    def getCallFlowFunction(self, callStmt, destinationMethod):
        pass

    def getReturnFlowFunction(self, callSite, calleeMethod, exitStmt, returnSite):
        pass

    def getCallToReturnFlowFunction(self, callSite, returnSite):
        pass
