from ...infoflowmanager import InfoflowManager
from ...data.abstraction import Abstraction

"""import TaintPropagationResults
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
import ITaintPropagationRule"""


class PropagationRuleManager:

	def __init__(self, manager, zero_value, results):
		self.manager = InfoflowManager()
		self.zero_value = Abstraction()
		self.results = TaintPropagationResults()
		self.rules = []
		self.manager = manager
		self.zero_value = zero_value
		self.results = results

		rule_list = []

		rule_list.append(SourcePropagationRule(manager, zero_value, results))
		rule_list.append(SinkPropagationRule(manager, zero_value, results))
		rule_list.append(StaticPropagationRule(manager, zero_value, results))

		if manager.getConfig().getEnableArrayTracking():
			rule_list.append(ArrayPropagationRule(manager, zero_value, results))

		if manager.getConfig().getEnableExceptionTracking():
			rule_list.append(ExceptionPropagationRule(manager, zero_value, results))

		if manager.getTaintWrapper() is not None:
			rule_list.append(WrapperPropagationRule(manager, zero_value, results))
			
		if manager.getConfig().getImplicitFlowMode().trackControlFlowDependencies():
			rule_list.append(ImplicitPropagtionRule(manager, zero_value, results))
		
		rule_list.append(StrongUpdatePropagationRule(manager, zero_value, results))
		
		if manager.getConfig().getEnableTypeChecking():
			rule_list.append(TypingPropagationRule(manager, zero_value, results))
		
		rule_list.append(SkipSystemClassRule(manager, zero_value, results))
		
		if manager.getConfig().getStopAfterFirstKFlows() > 0:
			rule_list.append(StopAfterFirstKFlowsPropagationRule(manager, zero_value, results))

		self.rules = rule_list.toArray(ITaintPropagationRule[rule_list.size()])

	def apply_normal_flow_function(self, d1, source, stmt, dest_stmt, kill_source=None, kill_all=None):
		res = set([])
		if kill_source is None:
			kill_source = False
		for rule in self.rules:
			rule_out = rule.propagate_normal_flow(d1, source, stmt, dest_stmt, kill_source, kill_all)
			if kill_all is not None and kill_all.value:
				return None

			if rule_out is not None and not rule_out.is_empty():
				if res is None:
					res = list(rule_out)

				else:
					res.update(rule_out)

		if (kill_all is None or not kill_all.value) and not kill_source.value:
			if res is None:
				res = list()
				res.append(source)
			else:
				res = list(source)
		
		return res

	def apply_call_flow_function(self, d1, source, stmt, dest, kill_all):
		res = []
		for rule in self.rules:
			rule_out = rule.propagateCallFlow(d1, source, stmt, dest, kill_all)
			if kill_all.value:
				return None

			if rule_out is not None and not rule_out.is_empty():
				if res is None:
					res = list()
				else:
					res.extend(rule_out)
		return res

	def apply_call_to_return_flow_function(self, d1, source, stmt, kill_source, kill_all=None, no_append_source=False):
		res = []
		for rule in self.rules:
			rule_out = rule.propagateCallToReturnFlow(d1, source, stmt, kill_source, kill_all)
			if kill_all is not None and kill_all.value:
				return None
			if rule_out is not None and not rule_out.is_empty():
				if res is None:
					res = HashSet(rule_out)
				else:
					res.extend(rule_out)

		if not no_append_source and not kill_source.value:
			if res is None:
				res = list()
				res.append(source)
			else:
				res.append(source)

		return res

	def apply_return_flow_function(self, caller_d1s, source, stmt, ret_site, call_site, kill_all):
		res = []
		for rule in self.rules:
			rule_out = rule.propagateReturnFlow(caller_d1s, source, stmt, ret_site, call_site, kill_all)
			if kill_all is not None and kill_all.value:
				return None
			if rule_out is not None and not rule_out.is_empty():
				if res is None:
					res = list()
				else:
					res.extend(rule_out)
		return res

	def getRules(self):
		return self.rules
