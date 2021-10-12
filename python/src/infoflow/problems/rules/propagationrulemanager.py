from .sourcepropagationrule import SourcePropagationRule
from .sinkpropagationrule import SinkPropagationRule
from .staticpropagationrule import StaticPropagationRule
from .arraypropagationrule import ArrayPropagationRule
from .exceptionpropagationrule import ExceptionPropagationRule
from .wrapperpropagationrule import WrapperPropagationRule
from .implicitpropagtionrule import ImplicitPropagtionRule
from .strongupdatepropagationrule import StrongUpdatePropagationRule
from .typingpropagationrule import TypingPropagationRule
from .skipsystemclassrule import SkipSystemClassRule
from .stopafterfirstkflowspropagationrule import StopAfterFirstKFlowsPropagationRule
from ...infoflowconfiguration import ImplicitFlowMode
from ...infoflowmanager import InfoflowManager


class PropagationRuleManager:

	def __init__(self, manager, zero_value, results):
		"""

		:param InfoflowManager manager:
		:param zero_value:
		:param results:
		"""
		self.rules = []
		self.manager = manager
		self.zero_value = zero_value
		self.results = results

		rule_list = list()

		rule_list.append(SourcePropagationRule(manager, zero_value, results))
		rule_list.append(SinkPropagationRule(manager, zero_value, results))
		rule_list.append(StaticPropagationRule(manager, zero_value, results))

		if manager.config.enable_arrays:
			rule_list.append(ArrayPropagationRule(manager, zero_value, results))

		if manager.config.enable_exceptions:
			rule_list.append(ExceptionPropagationRule(manager, zero_value, results))

		if manager.taint_wrapper is not None:
			rule_list.append(WrapperPropagationRule(manager, zero_value, results))
			
		if manager.config.implicit_flow_mode is ImplicitFlowMode.AllImplicitFlows:
			rule_list.append(ImplicitPropagtionRule(manager, zero_value, results))
		
		rule_list.append(StrongUpdatePropagationRule(manager, zero_value, results))
		
		if manager.config.enable_type_checking:
			rule_list.append(TypingPropagationRule(manager, zero_value, results))
		
		rule_list.append(SkipSystemClassRule(manager, zero_value, results))
		
		if manager.config.stop_after_first_k_flows > 0:
			rule_list.append(StopAfterFirstKFlowsPropagationRule(manager, zero_value, results))

		self.rules = rule_list

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
			rule_out = rule.propagate_call_flow(d1, source, stmt, dest, kill_all)
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
			rule_out = rule.propagate_call_to_return_flow(d1, source, stmt, kill_source, kill_all)
			if kill_all is not None and kill_all.value:
				return None
			if rule_out is not None and not rule_out.is_empty():
				if res is None:
					res = list(rule_out)
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
			rule_out = rule.propagate_return_flow(caller_d1s, source, stmt, ret_site, call_site, kill_all)
			if kill_all is not None and kill_all.value:
				return None
			if rule_out is not None and not rule_out.is_empty():
				if res is None:
					res = list()
				else:
					res.extend(rule_out)
		return res
