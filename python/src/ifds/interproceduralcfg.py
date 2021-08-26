class InterproceduralCFG:
	
	def getMethodOf(self, n):
		pass

	def getPredsOf(self, u):
		pass
	
	def getSuccsOf(self, n):
		pass

	def getCalleesOfCallAt(self, n):
		pass

	def getCallersOf(self, m):
		pass

	def getCallsFromWithin(self, m):
		pass

	def getStartPointsOf(self, m):
		pass

	def getReturnSitesOfCallAt(self, n):
		pass

	def isCallStmt(self, stmt):
		pass

	def isExitStmt(self, stmt):
		pass
	
	def isStartPoint(self, stmt):
		pass

	def allNonCallStartNodes(self):
		pass
	
	def isFallThroughSuccessor(self, stmt, succ):
		pass
	
	def isBranchTarget(self, stmt, succ):
		pass
