import InfoflowManager
import Abstraction
import TaintPropagationResults
import SourcePropagationRule
import SinkPropagationRule
import StaticPropagationRule
import ArrayPropagationRule
import ExceptionPropagationRule
import WrapperPropagationRule
import ImplicitPropagtionRule
import StrongUpdatePropagationRule
import TypingPropagationRule
import SkipSystemClassRule
import StopAfterFirstKFlowsPropagationRule
import ITaintPropagationRule
import ByReferenceBoolean
import HashSet


class PropagationRuleManager:

	def __init__(self, manager, zeroValue, results):
		self.manager = InfoflowManager()
		self.zeroValue = Abstraction()
		self.results = TaintPropagationResults()
		self.rules = []
		self.manager = manager
		self.zeroValue = zeroValue
		self.results = results

		ruleList = []

		ruleList.add(SourcePropagationRule(manager, zeroValue, results))
		ruleList.add(SinkPropagationRule(manager, zeroValue, results))
		ruleList.add(StaticPropagationRule(manager, zeroValue, results))

		if manager.getConfig().getEnableArrayTracking():
			ruleList.add(ArrayPropagationRule(manager, zeroValue, results))

		if manager.getConfig().getEnableExceptionTracking():
			ruleList.add(ExceptionPropagationRule(manager, zeroValue, results))

		if manager.getTaintWrapper() is not None:
			ruleList.add(WrapperPropagationRule(manager, zeroValue, results))
			
		if manager.getConfig().getImplicitFlowMode().trackControlFlowDependencies():
			ruleList.add(ImplicitPropagtionRule(manager, zeroValue, results))
		
		ruleList.add(StrongUpdatePropagationRule(manager, zeroValue, results))
		
		if manager.getConfig().getEnableTypeChecking():
			ruleList.add(TypingPropagationRule(manager, zeroValue, results))
		
		ruleList.add(SkipSystemClassRule(manager, zeroValue, results))
		
		if manager.getConfig().getStopAfterFirstKFlows() > 0:
			ruleList.add(StopAfterFirstKFlowsPropagationRule(manager, zeroValue, results))

		self.rules = ruleList.toArray(ITaintPropagationRule[ruleList.size()])

	def applyNormalFlowFunction(self, d1,  source,  stmt,  destStmt, killSource=None, killAll=None):
		res = set([])
		if killSource is None:
			killSource = ByReferenceBoolean()
		for rule in self.rules:
			ruleOut = rule.propagateNormalFlow(d1, source, stmt, destStmt, killSource, killAll)
			if killAll is not None and killAll.value:
				return None

			if ruleOut is not None and not ruleOut.isEmpty():
				if res is None:
					res = HashSet(ruleOut)

				else:
					res.addAll(ruleOut)

		if (killAll is None or not killAll.value) and not killSource.value:
			if res is None:
				res = HashSet()
				res.add(source)
			else:
				res.add(source)
		
		return res

	def applyCallFlowFunction(self, d1, source, stmt, dest, killAll):
		res = []
		for rule in self.rules:
			ruleOut = rule.propagateCallFlow(d1, source, stmt, dest, killAll)
			if killAll.value: 
				return None

			if (ruleOut is not None and not ruleOut.isEmpty()):
				if res is None:
					res = HashSet(ruleOut)
				else:
					res.addAll(ruleOut)
		return res

	def applyCallToReturnFlowFunction(self, d1, source, stmt, killSource, killAll=None, noAddSource=False):
		res = []
		for rule in self.rules:
			ruleOut = rule.propagateCallToReturnFlow(d1, source, stmt, killSource, killAll)
			if killAll is not None and killAll.value:
				return None
			if ruleOut is not None and not ruleOut.isEmpty():
				if res is None:
					res = HashSet(ruleOut)
				else:
					res.addAll(ruleOut)

		if not noAddSource and not killSource.value:
			if res is None:
				res = HashSet()
				res.add(source)
			else:
				res.add(source)

		return res

	def applyReturnFlowFunction(self, callerD1s, source, stmt, retSite, callSite, killAll):
		res = []
		for rule in self.rules:
			ruleOut = rule.propagateReturnFlow(callerD1s, source, stmt, retSite, callSite, killAll)
			if killAll is not None and killAll.value:
				return None
			if ruleOut is not None and not ruleOut.isEmpty():
				if res is None:
					res = HashSet(ruleOut)
				else:
					res.addAll(ruleOut)
		return res

	def getRules(self):
		return self.rules
