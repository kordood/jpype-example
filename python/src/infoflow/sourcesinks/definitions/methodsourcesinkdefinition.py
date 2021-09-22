from .accesspathtuple import AccessPathTuple

from .abstractsourcesinkdefinition import AbstractSourceSinkDefinition
from ...misc.pyenum import PyEnum


CallType = PyEnum('MethodCall', 'Callback', 'Return')


class MethodSourceSinkDefinition(AbstractSourceSinkDefinition):

    def __init__(self, am=None, base_objects=None, parameters=None, return_values=None, call_type=None, category=None):
        if self.return_values is None:
            self.return_values = CallType
        super().__init__(category)
        self.method = am
        self.base_objects = None if self.base_objects is None or len(base_objects) <= 0 else base_objects
        self.parameters = parameters
        self.return_values = None if self.return_values is None or len(self.return_values) <= 0 else return_values
        self.call_type = call_type
        self.BASE_OBJ_SOURCE = None
        self.BASE_OBJ_SINK = None
        self.PARAM_OBJ_SOURCE = list()

    def is_empty(self):
        parameters_empty = True
        if self.parameters is not None:
            for param_set in self.parameters:
                if param_set is not None and not param_set.is_empty():
                    parameters_empty = False
                    break
        return (self.base_objects is None or self.base_objects.isEmpty()) \
               and parameters_empty and (self.return_values is None or self.return_values.isEmpty())

    def get_source_only_definition(self):
        base_sources = list()
        if self.base_objects is not None:
            for apt in self.base_objects:
                if apt.sink_source.is_source():
                    base_sources.append(apt)

        param_sources = list()
        if self.parameters is not None and self.parameters.length > 0:
            for i in range(0, self.parameters.length):
                apt_set = self.parameters[i]
                if apt_set is not None:
                    this_param = list()
                    param_sources[i] = this_param
                    for apt in apt_set:
                        if apt.sink_source.is_source():
                            this_param.append(apt)

        return_sources = list()
        if self.return_values is not None:
            for apt in self.return_values:
                if apt.sink_source.is_source():
                    return_sources.append(apt)

        mssd = self.build_new_definition(base_sources, param_sources, return_sources)
        return mssd

    def get_sink_only_definition(self):
        base_sinks = list()
        if self.base_objects is not None:
            for apt in self.base_objects:
                if apt.sink_source.is_sink():
                    base_sinks.append(apt)

        param_sinks = list()
        if self.parameters is not None:
            for i in range(0, self.parameters.length):
                apt_set = self.parameters[i]
                if apt_set is not None:
                    this_param = list()
                    param_sinks[i] = this_param
                    for apt in apt_set:
                        if apt.sink_source.is_sink():
                            this_param.append(apt)

        return_sinks = list()
        if self.return_values is not None:
            for apt in self.return_values:
                if apt.sink_source.is_sink():
                    return_sinks.append(apt)

        mssd = self.build_new_definition(base_sinks, param_sinks, return_sinks)
        return mssd

    def build_new_definition(self,
                             base_apts=None,
                             param_apts=None,
                             return_apts=None,
                             method_andclass=None,
                             filtered_base_objects=None,
                             filtered_parameters=None,
                             filtered_return_values=None,
                             call_type=None):
        if base_apts is None:
            return MethodSourceSinkDefinition(method_andclass, filtered_base_objects, filtered_parameters,
                                              filtered_return_values, call_type)
        else:
            definition = self.build_new_definition(self.method, base_apts, param_apts, return_apts, self.call_type)
            definition.category = self.category
            return definition

    def merge(self, other):
        if isinstance(other, MethodSourceSinkDefinition):
            other_method = other

            if other_method.base_objects is not None and not len(other_method.base_objects) <= 0:
                if self.base_objects is None:
                    self.base_objects = list()
                for apt in other_method.base_objects:
                    self.base_objects.append(apt)

            if other_method.parameters is not None and len(other_method.parameters) > 0:
                if self.parameters is None:
                    self.parameters = list()
                for i in range(0, len(other_method.parameters)):
                    self.add_parameter_definition(i, other_method.parameters[i])

            if other_method.return_values is not None and not len(other_method.return_values) <= 0:
                if self.return_values is None:
                    self.return_values = list()
                for apt in other_method.return_values:
                    self.return_values.append(apt)

    def add_parameter_definition(self, param_idx, param_defs):
        if param_defs is not None and not param_defs.isEmpty():
            old_set = self.parameters
            if old_set.length <= param_idx:
                new_set = old_set[:param_idx]
                self.parameters = new_set

            aps = self.parameters[param_idx]
            if aps is None:
                aps = dict(param_defs.size())
                self.parameters[param_idx] = aps
            aps.extends(param_defs)

    def get_base_object_source(self):
        if self.BASE_OBJ_SOURCE is None:
            self.BASE_OBJ_SOURCE = MethodSourceSinkDefinition(
                    AccessPathTuple().get_blank_source_tuple(), list(), None, self.call_type.MethodCall)
        return self.BASE_OBJ_SOURCE

    def get_base_object_sink(self):
        if self.BASE_OBJ_SINK is None:
            self.BASE_OBJ_SINK = MethodSourceSinkDefinition(AccessPathTuple().get_blank_sink_tuple(), list(), None,
                                                             self.call_type.MethodCall)
        return self.BASE_OBJ_SINK

    def __eq__(self, obj):
        if self == obj:
            return True
        if not super().__eq__(obj):
            return False
        other = obj
        if self.base_objects is None:
            if other.base_objects is not None:
                return False
        elif not self.base_objects.__eq__(other.base_objects):
            return False
        if self.return_values != other.call_type:
            return False
        if self.method is None:
            if other.method is not None:
                return False
        elif not self.method.__eq__(other.method):
            return False
        if self.parameters == other.parameters:
            return False
        if self.return_values is None:
            if other.return_values is not None:
                return False
        elif not self.return_values.__eq__(other.return_values):
            return False
        return True

    def create_parameter_source(self, index, call_type):
        if index < 5 and self.return_values == self.call_type.MethodCall:
            definition = self.PARAM_OBJ_SOURCE[index]
            if definition is None:
                params = AccessPathTuple().get_blank_source_tuple()
                definition = MethodSourceSinkDefinition(None, params, None, call_type)
                self.PARAM_OBJ_SOURCE[index] = definition
            return definition

        return MethodSourceSinkDefinition(None, AccessPathTuple().get_blank_source_tuple(), None, call_type)

    @staticmethod
    def create_return_source(call_type):
        return MethodSourceSinkDefinition(None, list(), AccessPathTuple().get_blank_source_tuple()), call_type

    def simplify(self):
        base_obj_source = self.get_base_object_source()
        base_obj_sink = self.get_base_object_sink()

        if self.__eq__(base_obj_source):
            return base_obj_source
        elif self.__eq__(base_obj_sink):
            return base_obj_sink
        else:
            for i in range(0, len(self.PARAM_OBJ_SOURCE)):
                definition = self.create_parameter_source(i, self.call_type)
                if self.__eq__(definition):
                    return definition
            return self

    def get_all_access_paths(self):
        aps = list()
        if self.base_objects is not None and not self.base_objects.isEmpty():
            aps.extend(self.base_objects)
        if self.return_values is not None and not self.return_values.isEmpty():
            aps.extend(self.return_values)
        if self.parameters is not None and self.parameters.length > 0:
            for paramAPs in self.parameters:
                if paramAPs is not None and not paramAPs.is_empty():
                    aps.extend(paramAPs)
        return aps

    def filter(self, access_paths):
        filtered_base_objects = list()
        if self.base_objects is not None and not self.base_objects.isEmpty():
            for ap in self.base_objects:
                if access_paths.contains(ap):
                    filtered_base_objects.append(ap)

        filtered_return_values = None
        if self.return_values is not None and not self.return_values.isEmpty():
            filtered_return_values = list()
            for ap in self.return_values:
                if access_paths.contains(ap):
                    filtered_return_values.append(ap)

        filtered_parameters = None
        if self.parameters is not None and self.parameters.length > 0:
            filtered_parameters = list()
            for i in range(0, self.parameters.length):
                if self.parameters[i] is not None and not self.parameters[i].is_empty():
                    filtered_parameters[i] = dict()
                    for ap in self.parameters[i]:
                        if access_paths.contains(ap):
                            filtered_parameters[i] = ap

        define = self.build_new_definition(self.method, filtered_base_objects, filtered_parameters,
                                            filtered_return_values, self.call_type)
        define.setCategory(self.category)
        return define
