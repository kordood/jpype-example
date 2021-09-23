from ..sootir.soot_statement import AssignStmt
#import BaseSelector
#import FlowFunctionType
from ..problems.flowfunction import FlowFunction
from ..misc.copymember import copy_member


class SolverNormalFlowFunction(FlowFunction):

	def __init__(self, flowfunctions, stmt, dest):
		copy_member(self, flowfunctions)
		self.stmt = stmt
		self.dest = dest

	def compute_targets(self, d1, source):
		if self.taint_propagation_handler is not None:
			self.taint_propagation_handler.notify_flow_in(self.stmt, source, self.manager,
														FlowFunctionType.NormalFlowFunction)

		res = self.compute_targets_internal(d1, source)
		return self.notify_out_flow_handlers(self.stmt, d1, source, res, FlowFunctionType.NormalFlowFunction)

	def compute_targets_internal(self, d1, source):
		new_source = None
		if not source.is_abstraction_active() and self.src == source.getActivationUnit():
			new_source = source.get_active_copy()
		else:
			new_source = source

		kill_source = False
		kill_all = False
		res = self.propagation_rules.apply_normal_flow_function(d1, new_source, self.stmt, self.dest, kill_source, kill_all)

		if kill_all.value:
			return list()

		if isinstance(self.src, AssignStmt):
			assign_stmt = self.src
			right = assign_stmt.getRightOp()
			right_vals = BaseSelector.selectBaseList(right, True)

			res_assign = self.create_new_taint_on_assignment(assign_stmt, right_vals, d1, new_source)
			if res_assign is not None and not res_assign.is_empty():
				if res is not None:
					res.add_all(res_assign)
					return res
				else:
					res = res_assign

		return list() if res is None or res.is_empty() else res