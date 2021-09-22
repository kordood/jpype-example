import logging
from .misc.pyenum import PyEnum

logger = Logging.getLogger(__file__)


SootIntegrationMode = PyEnum('CreateNewInstance', 'UseExistingInstance', 'UseExistingCallgraph')
CallgraphAlgorithm = PyEnum('AutomaticSelection', 'CHA', 'VTA', 'RTA', 'SPARK', 'GEOM', 'OnDemand')
AliasingAlgorithm = PyEnum('FlowSensitive', 'PtsBased', '_None', 'Lazy')
CodeEliminationMode = PyEnum('NoCodeElimination', 'PropagateConstants', 'RemoveSideEffectFreeCode')
DataFlowSolver = PyEnum('ContextFlowSensitive', 'FlowInsensitive', 'GarbageCollecting')
ImplicitFlowMode = PyEnum('NoImplicitFlows', 'ArrayAccesses', 'AllImplicitFlows')
PathReconstructionMode = PyEnum('NoPaths', 'Fast', 'Precise')
PathBuildingAlgorithm = PyEnum('Recursive', 'ContextSensitive', 'ContextInsensitive', 'ContextInsensitiveSourceFinder',
                               '_None')
StaticFieldTrackingMode = PyEnum('ContextFlowSensitive', 'ContextFlowInsensitive', '_None')
SourceSinkFilterMode = PyEnum('UseAllButExcluded', 'UseOnlyIncluded')
CategoryMode = PyEnum('Include', 'Exclude')
CallbackSourceMode = PyEnum('NoParametersAsSources', 'AllParametersAsSources', 'SourceListOnly')
LayoutMatchingMode = PyEnum('NoMatch', 'MatchAll', 'MatchSensitiveOnly')


class SourceSinkConfiguration:

    def __init__(self):
        self.callback_source_mode = CallbackSourceMode.SourceListOnly
        self.enable_lifecycle_sources = False
        self.layout_matching_mode = LayoutMatchingMode.MatchSensitiveOnly
        self.source_filter_mode = SourceSinkFilterMode.UseAllButExcluded
        self.sink_filter_mode = SourceSinkFilterMode.UseAllButExcluded

    def merge(self, ss_config):
        self.callback_source_mode = ss_config.callback_source_mode
        self.enable_lifecycle_sources = ss_config.enable_lifecycle_sources
        self.layout_matching_mode = ss_config.layout_matching_mode

        self.source_filter_mode = ss_config.source_filter_mode
        self.sink_filter_mode = ss_config.sink_filter_mode

    def __eq__(self, other):
        if self == other:
            return True
        if other is None:
            return False
        if self.callback_source_mode != other.callback_source_mode:
            return False
        if self.enable_lifecycle_sources != other.enable_lifecycle_sources:
            return False
        if self.layout_matching_mode != other.layout_matching_mode:
            return False
        if self.sink_filter_mode != other.sink_filter_mode:
            return False
        if self.source_filter_mode != other.source_filter_mode:
            return False
        return True


class PathConfiguration:

    def __init__(self):
        self.sequential_path_processing = False
        self.path_reconstruction_mode = PathReconstructionMode.NoPaths
        self.path_building_algorithm = PathBuildingAlgorithm.ContextSensitive
        self.max_call_stack_size = 30
        self.max_path_length = 75
        self.max_paths_per_abstraction = 15
        self.path_reconstruction_timeout = 0
        self.path_reconstruction_batch_size = 5

    def merge(self, path_config):
        self.sequential_path_processing = path_config.sequential_path_processing
        self.path_reconstruction_mode = path_config.path_reconstruction_mode
        self.path_building_algorithm = path_config.path_building_algorithm
        self.max_call_stack_size = path_config.max_call_stack_size
        self.max_path_length = path_config.max_path_length
        self.max_paths_per_abstraction = path_config.max_paths_per_abstraction
        self.path_reconstruction_timeout = path_config.path_reconstruction_timeout
        self.path_reconstruction_batch_size = path_config.path_reconstruction_batch_size

    def must_keep_statements(self):
        return self.path_reconstruction_mode.reconstructPaths() or self.path_building_algorithm == PathBuildingAlgorithm.ContextSensitive

    def __eq__(self, other):
        if self == other:
            return True
        if other is None:
            return False
        if self.max_call_stack_size != other.max_call_stack_size:
            return False
        if self.max_path_length != other.max_path_length:
            return False
        if self.max_paths_per_abstraction != other.max_paths_per_abstraction:
            return False
        if self.path_building_algorithm != other.path_building_algorithm:
            return False
        if self.path_reconstruction_batch_size != other.path_reconstruction_batch_size:
            return False
        if self.path_reconstruction_mode != other.path_reconstruction_mode:
            return False
        if self.path_reconstruction_timeout != other.path_reconstruction_timeout:
            return False
        if self.sequential_path_processing != other.sequential_path_processing:
            return False
        return True


class OutputConfiguration:
    def __init__(self):
        self.no_passed_values = False
        self.no_call_graph_fraction = False
        self.max_callers_in_output_file = 5
        self.result_serialization_timeout = 0

    def merge(self, output_config):
        self.no_passed_values = output_config.no_passed_values
        self.no_call_graph_fraction = output_config.no_call_graph_fraction
        self.max_callers_in_output_file = output_config.max_callers_in_output_file
        self.result_serialization_timeout = output_config.result_serialization_timeout

    def __eq__(self, other):
        if self == other:
            return True
        if other is None:
            return False
        if self.max_callers_in_output_file != other.max_callers_in_output_file:
            return False
        if self.no_call_graph_fraction != other.no_call_graph_fraction:
            return False
        if self.no_passed_values != other.no_passed_values:
            return False
        if self.result_serialization_timeout != other.result_serialization_timeout:
            return False
        return True


class SolverConfiguration:

    def __init__(self):
        self.data_flow_solver = DataFlowSolver.ContextFlowSensitive
        self.max_join_point_abstractions = 10
        self.max_callees_per_call_site = 75
        self.max_abstraction_path_length = 100

    def merge(self, solver_config):
        self.data_flow_solver = solver_config.data_flow_solver
        self.max_join_point_abstractions = solver_config.max_join_point_abstractions
        self.max_callees_per_call_site = solver_config.max_callees_per_call_site
        self.max_abstraction_path_length = solver_config.max_abstraction_path_length

    def __eq__(self, other):
        if self == other:
            return True
        if other is None:
            return False
        if self.data_flow_solver != other.data_flow_solver:
            return False
        if self.max_callees_per_call_site != other.max_callees_per_call_site:
            return False
        if self.max_join_point_abstractions != other.max_join_point_abstractions:
            return False
        if self.max_abstraction_path_length != other.max_abstraction_path_length:
            return False
        return True


class AccessPathConfiguration:

    def __init__(self):
        self.access_path_length = 5
        self.use_recursive_access_paths = True
        self.use_this_chain_reduction = True
        self.use_same_field_reduction = True

    def merge(self, config):
        self.access_path_length = config.access_path_length
        self.use_recursive_access_paths = config.use_recursive_access_paths
        self.use_this_chain_reduction = config.use_this_chain_reduction
        self.use_same_field_reduction = config.use_same_field_reduction

    def __eq__(self, other):
        if self == other:
            return True
        if other is None:
            return False
        if self.access_path_length != other.access_path_length:
            return False
        if self.use_recursive_access_paths != other.use_recursive_access_paths:
            return False
        if self.use_same_field_reduction != other.use_same_field_reduction:
            return False
        if self.use_this_chain_reduction != other.use_this_chain_reduction:
            return False
        return True


class InfoflowConfiguration:

    def __init__(self):
        self.pathAgnosticResults = True
        self.oneResultPerAccessPath = False
        self.mergeNeighbors = False

        self.stop_after_first_k_flows = 0
        self.implicit_flow_mode = ImplicitFlowMode.NoImplicitFlows
        self.enable_exceptions = True
        self.enable_arrays = True
        self.enable_array_size_tainting = True
        self.flow_sensitive_aliasing = True
        self.enable_type_checking = True
        self.ignore_flows_in_system_packages = False
        self.exclude_soot_library_classes = False
        self.max_thread_num = -1
        self.write_output_files = False
        self.log_sources_and_sinks = False
        self.enable_reflection = False
        self.enable_line_numbers = False
        self.enable_original_names = False

        self.inspect_sources = False
        self.inspect_sinks = False

        self.source_sink_configuration = SourceSinkConfiguration()
        self.path_configuration = PathConfiguration()
        self.output_configuration = OutputConfiguration()
        self.solver_configuration = SolverConfiguration()
        self.access_path_configuration = AccessPathConfiguration()

        self.callgraph_algorithm = CallgraphAlgorithm.AutomaticSelection
        self.aliasing_algorithm = AliasingAlgorithm.FlowSensitive
        self.code_elimination_mode = CodeEliminationMode.PropagateConstants
        self.static_field_tracking_mode = StaticFieldTrackingMode.ContextFlowSensitive
        self.soot_integration_mode = SootIntegrationMode.CreateNewInstance

        self.taint_analysis_enabled = True
        self.incremental_result_reporting = False
        self.data_flow_timeout = 0
        self.memory_threshold = 0.9
        self.one_source_at_a_time = False

        self.base_directory = ""

    def merge(self, config):
        self.stop_after_first_k_flows = config.stop_after_first_k_flows
        self.implicit_flow_mode = config.implicit_flow_mode
        self.enable_exceptions = config.enable_exceptions
        self.enable_arrays = config.enable_arrays
        self.enable_array_size_tainting = config.enable_array_size_tainting
        self.flow_sensitive_aliasing = config.flow_sensitive_aliasing
        self.enable_type_checking = config.enable_type_checking
        self.ignore_flows_in_system_packages = config.ignore_flows_in_system_packages
        self.exclude_soot_library_classes = config.exclude_soot_library_classes
        self.max_thread_num = config.max_thread_num
        self.write_output_files = config.write_output_files
        self.log_sources_and_sinks = config.log_sources_and_sinks
        self.enable_reflection = config.enable_reflection
        self.enable_line_numbers = config.enable_line_numbers
        self.enable_original_names = config.enable_original_names

        self.path_configuration.merge(config.path_configuration)
        self.output_configuration.merge(config.output_configuration)
        self.solver_configuration.merge(config.solver_configuration)
        self.access_path_configuration.merge(config.access_path_configuration)

        self.callgraph_algorithm = config.callgraph_algorithm
        self.aliasing_algorithm = config.aliasing_algorithm
        self.code_elimination_mode = config.code_elimination_mode
        self.static_field_tracking_mode = config.static_field_tracking_mode
        self.soot_integration_mode = config.soot_integration_mode

        self.inspect_sources = config.inspect_sources
        self.inspect_sinks = config.inspect_sinks

        self.taint_analysis_enabled = config.write_output_files
        self.incremental_result_reporting = config.incremental_result_reporting
        self.data_flow_timeout = config.data_flow_timeout
        self.memory_threshold = config.memory_threshold
        self.one_source_at_a_time = config.one_source_at_a_time

        self.base_directory = config.base_directory

    def printSummary(self):
        if self.static_field_tracking_mode == StaticFieldTrackingMode._None:
            logger.warn("field tracking is disabled, results may be incomplete")
        if not self.flow_sensitive_aliasing:
            logger.warn("Using flow-insensitive alias tracking, results may be imprecise")

        if self.implicit_flow_mode == ImplicitFlowMode.AllImplicitFlows:
            logger.info("Implicit flow tracking is enabled")
        elif self.implicit_flow_mode == ImplicitFlowMode.ArrayAccesses:
            logger.info("Tracking of implicit array accesses is enabled")
        elif self.implicit_flow_mode == ImplicitFlowMode.NoImplicitFlows:
            logger.info("Implicit flow tracking is NOT enabled")

        if self.enable_exceptions:
            logger.info("Exceptional flow tracking is enabled")
        else:
            logger.info("Exceptional flow tracking is NOT enabled")
        logger.info("Running with a maximum access path length of " + str(self.access_path_configuration.access_path_length))
        if self.pathAgnosticResults:
            logger.info("Using path-agnostic result collection")
        else:
            logger.info("Using path-sensitive result collection")
        if self.access_path_configuration.use_recursive_access_paths:
            logger.info("Recursive access path shortening is enabled")
        else:
            logger.info("Recursive access path shortening is NOT enabled")
        logger.info("Taint analysis enabled: " + str(self.taint_analysis_enabled))
        if self.one_source_at_a_time:
            logger.info("Running with one source at a time")
        logger.info("Using alias algorithm " + self.aliasing_algorithm)
