class InterproceduralCFG:
	
	def get_method_of(self, n):
		pass

	def get_preds_of(self, u):
		pass
	
	def get_succs_of(self, n):
		pass

	def get_callees_of_call_at(self, n):
		pass

	def get_callers_of(self, m):
		pass

	def get_calls_from_within(self, m):
		pass

	def get_start_points_of(self, m):
		pass

	def get_return_sites_of_call_at(self, n):
		pass

	def is_call_stmt(self, stmt):
		pass

	def is_exit_stmt(self, stmt):
		pass
	
	def is_start_point(self, stmt):
		pass

	def all_non_call_start_nodes(self):
		pass
	
	def is_fall_through_successor(self, stmt, succ):
		pass
	
	def is_branch_target(self, stmt, succ):
		pass
