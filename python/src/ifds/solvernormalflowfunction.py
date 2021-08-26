from flowfunction import FlowFunction


class SolverNormalFlowFunction(FlowFunction):

	def computeTargets(self, source):
		return self.computeTargets(None, source)

	def _computeTargets(self, d1, d2):
		pass
