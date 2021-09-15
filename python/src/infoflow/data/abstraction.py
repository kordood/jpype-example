from copy import copy

from .sourcecontext import SourceContext
from .accesspath import AccessPath
from ..infoflowconfiguration import InfoflowConfiguration
from ..misc.copymember import copy_member
from __future__ import annotations

class Abstraction:

    def __init__(self, ap_to_taint: AccessPath =None, definition=None, source_val: AccessPath =None, source_stmt=None, user_data=None,
                 source_context: SourceContext =None, exception_thrown: bool =None, is_implicit: bool =None, p: AccessPath =None, original: Abstraction=None):
        self.flow_sensitive_aliasing = True
        self.predecessor = None
        self.corresponding_call_site = None
        self.postdominators = None
        self.depends_on_cut_ap = False
        self.path_flags = None
        self.propagation_path_length = 0

        if p is None:
            self.source_context = source_context if source_context else SourceContext( definition, source_val, source_stmt,
                                                                                    user_data )
            self.access_path = ap_to_taint if ap_to_taint else source_val
            self.activation_unit = None
            self.exception_thrown = exception_thrown

            self.neighbors = None
            self.is_implicit = is_implicit
            self.current_stmt = None if source_context is None else source_context.stmt

        else:
            if original is None:
                self.source_context = None
                self.exception_thrown = False
                self.activation_unit = None
                self.is_implicit = False
            else:
                self.source_context = original.source_context
                self.exception_thrown = original.exception_thrown
                self.activation_unit = original.activation_unit
                assert self.activation_unit is None or self.flow_sensitive_aliasing

                self.postdominators = None if original.postdominators is None else list( original.postdominators )

                self.depends_on_cut_ap = original.depends_on_cut_ap
                self.is_implicit = original.is_implicit

            self.access_path = p
            self.neighbors = None
            self.current_stmt = None

    def initialize(self, config: InfoflowConfiguration):
        flow_sensitive_aliasing = config.flow_sensitive_aliasing

    def derive_inactive_abstraction(self, activation_unit):
        if not self.flow_sensitive_aliasing:
            assert self.is_abstraction_active()
            return self

        if not self.is_abstraction_active():
            return self

        a = self.derive_new_abstraction_mutable( self.access_path, None )
        if a is None:
            return None

        a.postdominators = None
        a.activation_unit = activation_unit
        a.depends_on_cut_ap |= a.access_path.cutOffApproximation
        return a

    def derive_new_abstraction(self, p: AccessPath, current_stmt, is_implicit: bool =None):
        is_implicit = is_implicit if is_implicit else self.is_implicit
        if self.access_path == p and self.current_stmt == current_stmt and self.is_implicit == is_implicit:
            return self

        abs = self.derive_new_abstraction_mutable( p, current_stmt )
        if abs is None:
            return None

        abs.is_implicit = is_implicit
        return abs

    def derive_new_abstraction_mutable(self, p: AccessPath, current_stmt):
        if p is None:
            return None

        if self.access_path == p and self.current_stmt == current_stmt:
            abs = copy(self)
            abs.current_stmt = current_stmt
            return abs

        abs = Abstraction( p, self )
        abs.predecessor = self
        abs.current_stmt = current_stmt
        abs.propagation_path_length = self.propagation_path_length + 1

        if not abs.access_path.is_empty():
            abs.postdominators = None
        if not abs.is_abstraction_active():
            abs.depends_on_cut_ap = abs.depends_on_cut_ap or p.isCutOffApproximation()

        abs.source_context = None
        return abs

    def derive_new_abstraction_on_throw(self, throw_stmt):
        abs = copy(self)

        abs.current_stmt = throw_stmt
        abs.source_context = None
        abs.exception_thrown = True
        return abs

    def derive_new_abstraction_on_catch(self, ap: AccessPath):
        assert self.exception_thrown
        abs = self.derive_new_abstraction_mutable( ap, None )
        if abs is None:
            return None

        abs.exception_thrown = False
        return abs

    def is_abstraction_active(self):
        return self.activation_unit is None

    def get_active_copy(self):
        if self.is_abstraction_active():
            return self

        a = copy(self)
        a.source_context = None
        a.activation_unit = None
        return a

    def derive_conditional_abstraction_enter(self, postdom, conditional_unit):
        assert self.is_abstraction_active()

        if self.postdominators is not None and postdom in self.postdominators:
            return self

        abs = self.derive_new_abstraction_mutable( AccessPath.emptyAccessPath, conditional_unit ) ##emptyAccessPath -> java에서 static 이더라구요
        if abs is None:
            return None

        if abs.postdominators is None:
            abs.postdominators = list( postdom )
        else:
            abs.postdominators.a( 0, postdom )
        return abs

    def derive_conditional_abstraction_call(self, conditional_call_site):
        assert self.is_abstraction_active()
        assert conditional_call_site is not None

        abs = self.derive_new_abstraction_mutable( AccessPath.emptyAccessPath, conditional_call_site )
        if abs is None:
            return None

        abs.postdominators = None

        return abs

    def drop_top_postdominator(self):
        if self.postdominators is None or len(self.postdominators) <= 0:
            return self

        abs = copy(self)
        abs.source_context = None
        abs.postdominators.remove( 0 )
        return abs

    def get_top_postdominator(self):
        if self.postdominators is None or len(self.postdominators) <= 0:
            return None
        return self.postdominators[0]

    def is_top_postdominator(self, sm):
        uc = self.get_top_postdominator()
        if uc is None:
            return False
        return uc.getMethod() == sm

    def copy(self):
        abs = Abstraction( self.access_path, self )
        abs.predecessor = self
        abs.neighbors = None
        abs.current_stmt = None
        abs.corresponding_call_site = None
        abs.propagation_path_length = self.propagation_path_length + 1

        assert abs == self
        return abs

    def __eq__(self, other):
        if self == other:
            return True
        if other is None:
            return False
        other = other

        if self.__hash__ != 0 and other.hashCode != 0 and self.__hash__ != other.hashCode:
            return False

        if self.access_path is None:
            if other.access_path is not None:
                return False
        elif not self.access_path == other.access_path:
            return False

        return self.local_equals( other )

    def local_equals(self, other):
        if self.source_context is None:
            if other.source_context is not None:
                return False
        elif not self.source_context == other.source_context:
            return False
        if self.activation_unit is None:
            if other.activation_unit is not None:
                return False
        elif not self.activation_unit == other.activation_unit:
            return False
        if self.exception_thrown != other.exception_thrown:
            return False
        if self.postdominators is None:
            if other.postdominators is not None:
                return False
        elif not self.postdominators == other.postdominators:
            return False
        if self.depends_on_cut_ap != other.depends_on_cut_ap:
            return False
        if self.is_implicit != other.is_implicit:
            return False
        return True

    def entails(self, other):
        if self.access_path is None:
            if other.access_path is not None:
                return False
        elif not self.access_path.entails(other.access_path):
            return False
        return self.local_equals( other )

    def add_neighbor(self, original_abstraction: Abstraction):
        InfoflowConfiguration().mergeNeighbors = False
        if original_abstraction == self:
            return False

        if self.predecessor == original_abstraction.predecessor \
                and self.current_stmt == original_abstraction.current_stmt \
                and self.predecessor == original_abstraction.predecessor:
            return False

        if self.neighbors is None:
            self.neighbors = set()
        elif InfoflowConfiguration().mergeNeighbors:
            for nb in self.neighbors:
                if nb == original_abstraction:
                    return False
                if original_abstraction.predecessor == nb.predecessor \
                    and original_abstraction.current_stmt == nb.current_stmt \
                    and original_abstraction.corresponding_call_site == nb.corresponding_call_site:
                    return False

        return self.neighbors.add( original_abstraction )

    def get_zero_abstraction(self, flow_sensitive_aliasing: bool):
        zero_value = Abstraction(AccessPath.zeroAccessPath , None, False, False) ##zeroAccessPath -> java에서 static 이더라구요
        Abstraction.flow_sensitive_aliasing = flow_sensitive_aliasing
        return zero_value
    
    
    """
    def register_path_flag(self, id, max_size):
        if self.path_flags is None or self.path_flags.size() < max_size:
            if self.path_flags is None:
                pf = set( max_size )
                path_flags = pf
            elif self.path_flags.size() < max_size:
                pf = AtomicBitSet( max_size )
                for i in range( 0, self.path_flags.size() ):
                    if self.path_flags.get( i ):
                        pf.set( i )
    
                path_flags = pf
    
        return self.path_flags.set( id )
    """

    def inject_source_context(self, source_context: SourceContext):
        if self.source_context is not None and self.source_context == source_context:
            return self
    
        abs = copy(self)
        abs.predecessor = None
        abs.neighbors = None
        abs.source_context = source_context
        abs.current_stmt = self.current_stmt
        return abs
