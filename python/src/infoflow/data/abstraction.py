from copy import copy

from .sourcecontext import SourceContext
from .accesspath import AccessPath
from ..infoflowconfiguration import InfoflowConfiguration


class Abstraction:

    def __init__(self, definition=None, source_val=None, source_stmt=None, user_data=None, exception_thrown=None,
                 is_implicit=None):
        """
        :param AccessPath ap_to_taint:
        :param definition:
        :param AccessPath source_val:
        :param source_stmt:
        :param user_data:
        :param SourceContext source_context:
        :param bool exception_thrown:
        :param bool is_implicit:
        :param AccessPath p:
        :param Abstraction original:
        """
        self.flow_sensitive_aliasing = True
        self.predecessor = None
        self.corresponding_call_site = None
        self.postdominators = None
        self.depends_on_cut_ap = False
        self.path_flags = None
        self.propagation_path_length = 0

        if not isinstance(definition, AccessPath):
            arg1 = source_val
            arg2 = SourceContext(definition, source_val, source_stmt, user_data)
            arg3 = exception_thrown
            arg4 = is_implicit
            definition = arg1
            source_val = arg2
            source_stmt = arg3
            user_data = arg4

        if isinstance(source_val, Abstraction):
            p = definition
            original = source_val

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
    
                self.postdominators = None if original.postdominators is None else list(original.postdominators)
    
                self.depends_on_cut_ap = original.depends_on_cut_ap
                self.is_implicit = original.is_implicit
    
            self.access_path = p
            self.neighbors = None
            self.current_stmt = None

        else:
            ap_to_taint = definition
            source_context = source_val
            exception_thrown = source_stmt
            is_implicit = user_data
    
            self.sourceContext = source_context
            self.accessPath = ap_to_taint
            self.activationUnit = None
            self.exception_thrown = exception_thrown

            self.neighbors = None
            self.is_implicit = is_implicit
            self.currentStmt = None if source_context is None else source_context.stmt

    def initialize(self, config):
        """

        :param InfoflowConfiguration config:
        :return:
        """
        self.flow_sensitive_aliasing = config.flow_sensitive_aliasing

    def derive_inactive_abstraction(self, activation_unit):
        """

        :param activation_unit:
        :return:
        """
        if not self.flow_sensitive_aliasing:
            assert self.is_abstraction_active()
            return self

        if not self.is_abstraction_active():
            return self

        a = self.derive_new_abstraction_mutable(self.access_path, None)
        if a is None:
            return None

        a.postdominators = None
        a.activation_unit = activation_unit
        a.depends_on_cut_ap |= a.access_path.cut_off_approximation
        return a

    def derive_new_abstraction(self, p, current_stmt, is_implicit=None):
        """

        :param AccessPath p:
        :param current_stmt:
        :param is_implicit:
        :return:
        """
        is_implicit = is_implicit if is_implicit else self.is_implicit
        if self.access_path == p and self.current_stmt == current_stmt and self.is_implicit == is_implicit:
            return self

        abstraction = self.derive_new_abstraction_mutable(p, current_stmt)
        if abstraction is None:
            return None

        abstraction.is_implicit = is_implicit
        return abstraction

    def derive_new_abstraction_mutable(self, p, current_stmt):
        if p is None:
            return None

        if self.access_path == p and self.current_stmt == current_stmt:
            abstraction = copy(self)
            abstraction.current_stmt = current_stmt
            return abstraction

        abstraction = Abstraction(p, self)
        abstraction.predecessor = self
        abstraction.current_stmt = current_stmt
        abstraction.propagation_path_length = self.propagation_path_length + 1

        if not abstraction.access_path.is_empty():
            abstraction.postdominators = None
        if not abstraction.is_abstraction_active():
            abstraction.depends_on_cut_ap = abstraction.depends_on_cut_ap or p.cut_off_approximation

        abstraction.source_context = None
        return abstraction

    def derive_new_abstraction_on_throw(self, throw_stmt):
        abstraction = copy(self)

        abstraction.current_stmt = throw_stmt
        abstraction.source_context = None
        abstraction.exception_thrown = True
        return abstraction

    def derive_new_abstraction_on_catch(self, ap):
        """

        :param AccessPath ap:
        :return:
        """
        assert self.exception_thrown
        abstraction = self.derive_new_abstraction_mutable(ap, None)
        if abstraction is None:
            return None

        abstraction.exception_thrown = False
        return abstraction

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

        abstraction = self.derive_new_abstraction_mutable(AccessPath(), conditional_unit)
        if abstraction is None:
            return None

        if abstraction.postdominators is None:
            abstraction.postdominators = list(postdom)
        else:
            abstraction.postdominators[0] = postdom
        return abstraction

    def derive_conditional_abstraction_call(self, conditional_call_site):
        assert self.is_abstraction_active()
        assert conditional_call_site is not None

        abstraction = self.derive_new_abstraction_mutable(AccessPath(), conditional_call_site)
        if abstraction is None:
            return None

        abstraction.postdominators = None

        return abstraction

    def drop_top_postdominator(self):
        if self.postdominators is None or len(self.postdominators) <= 0:
            return self

        abstraction = copy(self)
        abstraction.source_context = None
        abstraction.postdominators.remove(0)
        return abstraction

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
        abstraction = Abstraction(self.access_path, self)
        abstraction.predecessor = self
        abstraction.neighbors = None
        abstraction.current_stmt = None
        abstraction.corresponding_call_site = None
        abstraction.propagation_path_length = self.propagation_path_length + 1

        assert abstraction == self
        return abstraction

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

        return self.local_equals(other)

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
        return self.local_equals(other)

    def add_neighbor(self, original_abstraction):
        """

        :param Abstraction original_abstraction:
        :return:
        """
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

        return self.neighbors.add(original_abstraction)

    @staticmethod
    def get_zero_abstraction(flow_sensitive_aliasing):
        zero_value = Abstraction(AccessPath(),
                                 None,
                                 False,
                                 False)
        Abstraction.flow_sensitive_aliasing = flow_sensitive_aliasing
        return zero_value

    """
    def register_path_flag(self, id, max_size):
        if self.path_flags is None or self.path_flags.size() < max_size:
            if self.path_flags is None:
                pf = set(max_size)
                path_flags = pf
            elif self.path_flags.size() < max_size:
                pf = AtomicBitSet(max_size)
                for i in range(0, self.path_flags.size()):
                    if self.path_flags.get(i):
                        pf.set(i)
    
                path_flags = pf
    
        return self.path_flags.set(id)
    """

    def inject_source_context(self, source_context):
        if self.source_context is not None and self.source_context == source_context:
            return self

        abstraction = copy(self)
        abstraction.predecessor = None
        abstraction.neighbors = None
        abstraction.source_context = source_context
        abstraction.current_stmt = self.current_stmt
        return abstraction
