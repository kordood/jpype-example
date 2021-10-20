
from .androidsourcesinkmanager import AndroidSourceSinkManager
from ...misc import get_invoke_expr, contains_invoke_expr
from ...sourcesinks.definitions.abstractsourcesinkdefinition import AbstractSourceSinkDefinition
from ...sourcesinks.definitions.methodsourcesinkdefinition import MethodSourceSinkDefinition, CallType
from ...sourcesinks.definitions.fieldsourcesinkdefinition import FieldSourceSinkDefinition
from ...sourcesinks.definitions.stataementsourcesinkdefinition import StatementSourceSinkDefinition
from ...sourcesinks.manger.sinkinfo import SinkInfo
from ...sootir.soot_statement import IdentityStmt, InvokeStmt, DefinitionStmt, AssignStmt
from ...sootir.soot_expr import SootInvokeExpr
from ...sootir.soot_value import SootParamRef
from ...util.systemclasshandler import SystemClassHandler


class AccessPathBasedSourceSinkManager(AndroidSourceSinkManager):

    def create_source_info(self, s_call_site, manager, define):
        if define is None:
            return None

        if not isinstance(define, AbstractSourceSinkDefinition):
            return super().create_source_info(s_call_site, manager, define)
        ap_def = define

        if ap_def.is_empty():
            return super().create_source_info(s_call_site, manager, define)

        aps = list()
        ap_tuples = list()

        if isinstance(define, MethodSourceSinkDefinition):
            method_def = define
    
            call_type = method_def.call_type
            if call_type == CallType.Callback:
                if isinstance(s_call_site, IdentityStmt):
                    identity_stmt = s_call_site
                    if isinstance(identity_stmt.right_op, SootParamRef):
                        param_ref = identity_stmt.right_op
                        if method_def.parameters is not None and method_def.parameters.length > param_ref.index:
                            for apt in method_def.parameters[param_ref.index]:
                                aps.append(apt.toAccessPath(identity_stmt.left_op, manager, False))
                                ap_tuples.append(apt)
            elif call_type == CallType.MethodCall:
                if isinstance(s_call_site, InvokeStmt) and isinstance(get_invoke_expr(s_call_site), SootInvokeExpr) and method_def.base_objects is not None:
                    base_val = (get_invoke_expr(s_call_site)).getBase()
                    for apt in method_def.base_objects:
                        if apt.sink_source.isSource():
                            aps.append(apt.toAccessPath(base_val, manager, True))
                            ap_tuples.append(apt)
    
                if isinstance(s_call_site, DefinitionStmt) and method_def.return_values is not None:
                    return_val = s_call_site.left_op
                    for apt in method_def.return_values:
                        if apt.sink_source.isSource():
                            aps.append(apt.toAccessPath(return_val, manager, False))
                            ap_tuples.append(apt)
    
                if contains_invoke_expr(s_call_site) and method_def.parameters is not None and method_def.parameters.length > 0:
                    for i in range(0, get_invoke_expr(s_call_site).getArgCount()):
                        if method_def.parameters.length > i:
                            for apt in method_def.parameters[i]:
                                if apt.sink_source.isSource():
                                    aps.append(apt.toAccessPath(get_invoke_expr(s_call_site).getArg(i), manager, True))
                                    ap_tuples.append(apt)
    
            else:
                return None

    def get_sink_info(self, s_call_site, manager, source_access_path):
        define = self.get_sink_definition(s_call_site, manager, source_access_path)
        if define is None:
            return None

        if not isinstance(define, AbstractSourceSinkDefinition):
            return super().get_sink_info(s_call_site, manager, source_access_path)
        ap_def = define

        if ap_def.is_empty() and s_call_site.containsInvokeExpr():
            if SystemClassHandler().is_taint_visible(source_access_path, get_invoke_expr(s_call_site).getMethod()):
                return SinkInfo(define)
            else:
                return None

        if source_access_path is None:
            return SinkInfo(define)

        if isinstance(define, MethodSourceSinkDefinition):
            method_def = define
            if method_def.call_type == CallType.Return:
                return SinkInfo(define)

            iexpr = get_invoke_expr(s_call_site)
            if isinstance(iexpr, SootInvokeExpr) and method_def.base_objects is not None:
                iiexpr = iexpr
                if iiexpr.getBase() == source_access_path.getPlainValue():
                    for apt in method_def.base_objects:
                        if apt.sink_source.is_sink() and self.access_path_matches(source_access_path, apt):
                            return SinkInfo(ap_def.filter(list(apt)))

            if method_def.parameters is not None and method_def.parameters.length > 0:
                for i in range(0, get_invoke_expr(s_call_site).getArgCount()):
                    if get_invoke_expr(s_call_site).getArg(i) == source_access_path.getPlainValue():
                        if method_def.parameters.length > i:
                            for apt in method_def.parameters[i]:
                                if apt.sink_source.is_sink() and self.access_path_matches(source_access_path, apt):
                                    return SinkInfo(ap_def.filter(list(apt)))

        elif isinstance(define, FieldSourceSinkDefinition):
            field_def = define

            if isinstance(s_call_site, AssignStmt) and field_def.access_paths is not None:
                for apt in field_def.access_paths:
                    if apt.sink_source.is_sink() and self.access_path_matches(source_access_path, apt):
                        return SinkInfo(ap_def.filter(list(apt)))

        elif isinstance(define, StatementSourceSinkDefinition):
            ssdef = define
            for apt in ssdef.access_paths:
                if apt.sink_source.is_sink() and self.access_path_matches(source_access_path, apt):
                    return SinkInfo(ap_def.filter(list(apt)))

        return None

    def access_path_matches(self, source_access_path, apt):
        if apt.fields is None or len(apt.fields) == 0 or source_access_path is None:
            return True

        for i in range(0, len(apt.fields)):
            if i >= source_access_path.getFieldCount():
                return source_access_path.getTaintSubFields()

            if not source_access_path.fields[i].getName().equals(apt.fields[i]):
                return False

        return True
