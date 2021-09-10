from .infoflowconfiguration import InfoflowConfiguration
from .solver.ifdssolversingle import IFDSSolver


class InfoflowManager:

    def __init__(self, config: InfoflowConfiguration, forward_solver: IFDSSolver, icfg, source_sink_manager, taint_wrapper, hierarchy,
                 access_path_factory, global_taint_manager):
        self.config = config
        self.forward_solver = forward_solver
        self.icfg = icfg
        self.source_sink_manager = source_sink_manager
        self.taint_wrapper = taint_wrapper
        self.hierarchy = hierarchy
        self.access_path_factory = access_path_factory
        self.global_taint_manager = global_taint_manager
