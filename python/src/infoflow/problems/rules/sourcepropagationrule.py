
from .abstracttaintpropagationrule import AbstractTaintPropagationRule
from ...data.abstraction import Abstraction
from ...util.typeutils import TypeUtils
from ...sourcesinks.definitions.methodsourcesinkdefinition import MethodSourceSinkDefinition, CallType


class SourcePropagationRule(AbstractTaintPropagationRule):

    def propagate(self, d1, source, stmt, kill_source, kill_all):
        if source == self.zero_value:
            source_info = self.manager.source_sink_manager.getSourceInfo(stmt, self.manager)\
                if self.manager.source_sink_manager is not None else None
            kill_source.value = True

            if source_info is not None and len(source_info.access_path) > 0:
                res = list()
                for ap in source_info.access_path:

                    abs = Abstraction(definition=source_info.definition,
                                      source_val=ap,
                                      source_stmt=stmt,
                                      user_data=source_info.user_data,
                                      exception_thrown=False,
                                      is_implicit=False
                                     )
                    res.append(abs)

                    for vb in stmt.use_boxes:
                        if ap.startsWith(vb.getValue()):

                            if not TypeUtils(self.manager).is_string_type(vb.getValue().getType()) \
                                    or ap.getCanHaveImmutableAliases():
                                self.manager.aliasing.compute_aliases( d1, stmt, vb.getValue(), res,
                                                                       self.manager.icfg.getMethodOf(stmt), abs )

                    if stmt.containsInvokeExpr():
                        abs.corresponding_call_site = stmt

                return res

            if kill_all is not None:
                kill_all.value = True

        return None

    def propagate_normal_flow(self, d1, source, stmt, dest_stmt, kill_source, kill_all):
        return self.propagate(d1, source, stmt, kill_source, kill_all)

    def propagate_call_to_return_flow(self, d1, source, stmt, kill_source, kill_all):
        return self.propagate(d1, source, stmt, kill_source, None)

    def propagate_return_flow(self, caller_d1s, source, stmt, ret_site, call_site, kill_all):
        return None

    def propagate_call_flow(self, d1, source, stmt, dest, kill_all):

        if not self.manager.config.getInspectSources() and self.manager.source_sink_manager is not None:
            source_info = self.manager.source_sink_manager.getSourceInfo(stmt, self.manager)
            if source_info is not None and not self.is_callback_or_return(source_info.definition):
                kill_all.value = True

        if not self.manager.config.getInspectSinks() and self.manager.source_sink_manager is not None:
            isSink = self.manager.source_sink_manager.get_sink_info(stmt, self.manager,
                                                                    source.getAccessPath()) is not None
            if isSink:
                kill_all.value = True

        return None

    def is_callback_or_return(self, definition):
        if isinstance(definition, MethodSourceSinkDefinition):
            method_def = definition
            call_type = method_def.call_type
            return call_type == CallType.Callback or call_type == CallType.Return

        return False
