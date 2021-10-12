from ..data.abstractionatsink import AbstractionAtSink
from ..util.systemclasshandler import SystemClassHandler


class TaintPropagationResults:

	def __init__(self, manager):
		self.manager = manager
		self._results = dict()
		self.result_added_handlers = list()

	def add_result(self, result_abs):
		if self.manager.config.getIgnoreFlowsInSystemPackages() \
				and SystemClassHandler().is_class_in_system_package(
			self.manager.icfg.get_method_of(result_abs.sink_stmt).declaring_class.name
		):
			return True

		abstraction = result_abs.abstraction
		abstraction = abstraction.deriveNewAbstraction(abstraction.accesspath, result_abs.sink_stmt)
		abstraction.setCorrespondingCallSite(result_abs.sink_stmt)
		memory_manager = self.manager.forward_solver.memory_manager

		if memory_manager is not None:
			abstraction = memory_manager.handleMemoryObject(abstraction)
			if abstraction is None:
				return True

		result_abs = AbstractionAtSink(result_abs.sink_definition, abstraction, result_abs.sink_stmt)

		if self._results.get(result_abs) is None:
			self._results[result_abs] = result_abs.abstraction

		new_abs = self._results[result_abs]

		if new_abs != result_abs.abstraction:
			new_abs.add_neighbor(result_abs.abstraction)

		continue_analysis = True

		for handler in self.result_added_handlers:
			if not handler.on_result_available(result_abs):
				continue_analysis = False
		return continue_analysis

	@property
	def results(self):
		return self._results.keys()

	def add_result_available_handler(self, handler):
		self.result_added_handlers.append(handler)

	def __eq__(self, other):
		if self == other:
			return True
		if other is None:
			return False
		if self._results is None:
			if other.results is not None:
				return False
		elif self._results != other.results:
			return False
		return True
