import logging
from defaultjimpleifdstabulationproblem import DefaultJimpleIFDSTabulationProblem
import HashSet, HashMap, MyConcurrentHashMap
import ConcurrentHashSet
import DefinitionStmt
import CaughtExceptionRef
import FlowDroidEssentialMethodTag
import Abstraction
import SystemClassHandler

logger = logging.getLogger(__file__)


class AbstractInfoflowProblem(DefaultJimpleIFDSTabulationProblem):
    
    def __init__(self, manager):
        super().__init__(manager.getICFG())
        self.manager = manager
        self.initial_seeds = HashMap()
        self.taint_wrapper = None
        self.nc_handler = None
        self.zero_value = None
        self.solver = None
        self.taint_propagation_handler = None
        self.activation_units_to_call_sites = MyConcurrentHashMap()

        self.def_stmt = None
        self.decl_class = None

    def set_solver(self, solver):
        self.solver = solver

    def set_zero_value(self, zero_value):
        self.zero_value = zero_value

    def follow_returns_past_seeds(self):
        return True

    def set_taint_wrapper(self, wrapper):
        self.taint_wrapper = wrapper

    def set_native_call_handler(self, handler):
        self.nc_handler = handler

    def is_initial_method(self, sm):
        for u in self.initial_seeds.keySet():
            if self.interprocedural_cfg().get_method_of(u) == sm:
                return True
        return False

    def initial_seeds(self):
        return self.initial_seeds

    def auto_add_zero(self):
        return False

    def is_call_site_activating_taint(self, call_site, activation_unit):
        if not self.manager.getConfig().getFlowSensitiveAliasing():
            return False

        if activation_unit is None:
            return False
        call_sites = self.activation_units_to_call_sites.get(activation_unit)
        return call_sites is not None and call_sites.contains(call_site)

    def register_activation_call_site(self, call_site, callee, activation_abs):
        if not self.manager.getConfig().getFlowSensitiveAliasing():
            return False
        activation_unit = activation_abs.getactivation_unit()
        if activation_unit is None:
            return False

        call_sites = self.activation_units_to_call_sites.putIfAbsentElseGet(activation_unit, ConcurrentHashSet())
        if call_sites.contains(call_site):
            return False

        if not activation_abs.is_abstraction_active():
            if not callee.getActiveBody().getUnits().contains(activation_unit):
                found = False
                for au in call_sites:
                    if callee.getActiveBody().getUnits().contains(au):
                        found = True
                        break
                if not found:
                    return False

        return call_sites.add(call_site)

    def set_activation_units_to_call_sites(self, other):
        self.activation_units_to_call_sites = other.activation_units_to_call_sites

    def interprocedural_cfg(self):
        return super(AbstractInfoflowProblem, self).interprocedural_cfg()

    def add_initial_seeds(self, unit, seeds):
        if self.initial_seeds.containsKey(unit):
            self.initial_seeds.get(unit).addAll(seeds)
        else:
            self.initial_seeds.put(unit, HashSet(seeds))

    def has_initial_seeds(self):
        return not self.initial_seeds.is_empty()

    def get_initial_seeds(self):
        return self.initial_seeds

    def set_taint_propagation_handler(self, handler):
        self.taint_propagation_handler = handler

    def create_zero_value(self):
        if self.zero_value is None:
            self.zero_value = Abstraction.get_zero_abstraction( self.manager.getConfig().getFlowSensitiveAliasing() )
        return self.zero_value

    def get_zero_value(self):
        return self.zero_value

    def is_exception_handler(self, u):
        if isinstance(u, DefinitionStmt):
            self.def_stmt = u
            return isinstance(self.def_stmt.getRightOp(), CaughtExceptionRef)
        return False

    def notify_out_flow_handlers(self, stmt, d1, incoming, outgoing, function_type):
        if self.taint_propagation_handler is not None \
                and outgoing is not None \
                and not outgoing.isEmpty():
            outgoing = self.taint_propagation_handler.notifyFlowOut(stmt,
                                                                    d1,
                                                                    incoming,
                                                                    outgoing,
                                                                    self.manager,
                                                                    function_type)
        return outgoing

    def compute_values(self):
        return False

    def get_manager(self):
        return self.manager

    def is_excluded(self, sm):
        if sm.hasTag(FlowDroidEssentialMethodTag.TAG_NAME):
            return False

        if self.manager.getConfig().getExcludeSootLibraryClasses():
            self.decl_class = sm.getDeclaringClass()
            if self.decl_class is not None and self.decl_class.isLibraryClass():
                return True

        if self.manager.getConfig().getIgnoreFlowsInSystemPackages():
            self.decl_class = sm.getDeclaringClass()
            if self.decl_class is not None and SystemClassHandler.v().is_class_in_system_package( self.decl_class.getName() ):
                return True

        return False
