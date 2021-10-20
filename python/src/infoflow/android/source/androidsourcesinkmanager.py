import logging

from ...infoflowmanager import InfoflowManager
from ...infoflowconfiguration import LayoutMatchingMode
from ...data.accesspath import AccessPath
from ...misc import get_invoke_expr, get_callees_of_call_at, contains_invoke_expr
from ...sourcesinks.manger.basesourcesinkmanager import BaseSourceSinkManager
from ...sootir.soot_expr import SootInvokeExpr
from ...sootir.soot_statement import SootStmt, AssignStmt
from ...sootir.soot_value import SootIntConstant, SootInstanceFieldRef, SootStaticFieldRef, SootStringConstant, \
    SootLocal, SootNullConstant

logger = logging.getLogger(__file__)


class AndroidSourceSinkManager(BaseSourceSinkManager):

    def __init__(self, sources, sinks, callback_methods=None, config=None, layout_controls=None):
        super().__init__(sources, sinks, callback_methods, config)

        self.activity_find_view_by_id = "<android.app.Activity: android.view.View findViewById(int)>"
        self.view_find_view_by_id = "<android.view.View: android.view.View findViewById(int)>"

        self.sm_activity_find_view_by_id = None
        self.sm_view_find_view_by_id = None

        self.layout_controls = layout_controls
        self.resource_packages = None
        self.app_package_name = ""
        self.analyzed_layout_methods = list()
        self.icc_base_classes = None
        self.entry_point_utils = AndroidEntryPointUtils()

    def initialize(self):
        super().initialize()
        self.sm_activity_find_view_by_id = Scene.v().grabMethod(self.activity_find_view_by_id)
        self.sm_view_find_view_by_id = Scene.v().grabMethod(self.view_find_view_by_id)

        if self.icc_base_classes is None:
            self.icc_base_classes = [Scene.v().getSootClass("android.content.Context"),
                                     Scene.v().getSootClass("android.content.ContentResolver"),
                                     Scene.v().getSootClass("android.app.Activity")
                                     ]

    def find_resource(self, res_name, res_id, package_name):
        for pkg in self.resource_packages:
            matches = (package_name is None or package_name.isEmpty()) and pkg.package_name == self.app_package_name
            matches |= pkg.package_name == package_name
            if not matches:
                continue

            for declared_type in pkg.getDeclaredTypes():
                if declared_type.type_name == res_id:
                    res = declared_type.getFirstResource(res_name)
                    return res

        return None

    def find_last_res_id_assignment(self, stmt, local, cfg, done_set):
        if not done_set.append(stmt):
            return None

        if isinstance(stmt, AssignStmt):
            assign = stmt

            if assign.left_op == local:
                if isinstance(assign.right_op, SootIntConstant):
                    return assign.right_op.value
                elif isinstance(assign.right_op, SootInstanceFieldRef) or isinstance(assign.right_op, SootStaticFieldRef):
                    field = assign.right_op.field

                    for tag in field.getTags():
                        if isinstance(tag, IntegerConstantValueTag):
                            return tag.getIntValue()
                        else:
                            logger.error("Constant %s was of unexpected type" % str(field))
                elif isinstance(assign.right_op, SootInvokeExpr):
                    inv = assign.right_op

                    if inv.method_name == "getIdentifier" and inv.class_name == "android.content.res.Resources" \
                            and self.resource_packages is not None:
                        if len(inv.args) != 3:
                            logger.error("Invalid parameter count (%d) for call to getIdentifier" % len(inv.args))
                            return None

                        res_name = ""
                        res_id = ""
                        package_name = ""

                        if isinstance(inv.args[0], SootStringConstant):
                            res_name = inv.args[0].value
                        if isinstance(inv.args[1], SootStringConstant):
                            res_id = inv.args[1].value

                        third_arg = inv.args[2]
                        if isinstance(third_arg, SootStringConstant):
                            package_name = third_arg.value
                        elif isinstance(third_arg, SootLocal):
                            package_name = self.find_last_string_assignment(stmt, third_arg, cfg)
                        elif isinstance(third_arg, SootNullConstant):
                            return None
                        else:
                            logger.error("Unknown parameter type %s in call to getIdentifier" % inv.args[2].class_name)
                            return None

                        res = self.find_resource(res_name, res_id, package_name)
                        if res is not None:
                            return res.getResourceID()

        for pred in cfg.getPredsOf(stmt):
            if not isinstance(pred, SootStmt):
                continue
            last_assignment = self.find_last_res_id_assignment(pred, local, cfg, done_set)
            if last_assignment is not None:
                return last_assignment

        return None

    def find_last_string_assignment(self, stmt, local, cfg):
        work_list = list()
        seen = list()
        work_list.append(stmt)
        while len(work_list) > 0:
            stmt = work_list[0]
            work_list = work_list[1:]

            if isinstance(stmt, AssignStmt):
                assign = stmt
                if assign.left_op == local:
                    if isinstance(assign.right_op, SootStringConstant):
                        return assign.right_op.value

            for pred in cfg.getPredsOf(stmt):
                if not isinstance(pred, SootStmt):
                    continue

                s = pred
                if seen.append(s):
                    work_list.append(s)

        return None

    def get_layout_control(self, s_call_site, cfg):
        if self.layout_controls is None:
            return None

        ui_method = cfg.getMethodOf(s_call_site)
        if self.analyzed_layout_methods.append(ui_method):
            ConstantPropagatorAndFolder.v().transform(ui_method.getActiveBody())

        iexpr = s_call_site.getInvokeExpr()
        if iexpr.getArgCount() != 1:
            logger.error("Framework method call with unexpected number of arguments")
            return None

        res_id = self.value_provider.getValue(ui_method, s_call_site, iexpr.args[0], SootInteger)
        if res_id is None and isinstance(iexpr.args[0], SootLocal):
            res_id = self.find_last_res_id_assignment(s_call_site, iexpr.args[0], cfg,
                                                  list(cfg.getMethodOf(s_call_site).getActiveBody().getUnits().size()))

        if res_id is None:
            logger.debug(
                "Could not find assignment to local " + (iexpr.args[0]).getName() + " in method " + cfg.getMethodOf(
                    s_call_site).getSignature())
            return None

        control = self.layout_controls[id]
        if control is None:
            return None
        return control

    def get_ui_source_definition(self, s_call_site, cfg):
        if self.source_sink_config.getLayoutMatchingMode() == LayoutMatchingMode.NoMatch \
                or not contains_invoke_expr(s_call_site):
            return None

        if not isinstance(s_call_site, AssignStmt):
            return None

        ie = get_invoke_expr(s_call_site)
        callee = ie.getMethod()

        is_resource_call = callee == self.sm_activity_find_view_by_id or callee == self.sm_view_find_view_by_id
        if not is_resource_call:
            for cfgCallee in get_callees_of_call_at(s_call_site, cfg):
                if cfgCallee == self.sm_activity_find_view_by_id or cfgCallee == self.sm_view_find_view_by_id:
                    is_resource_call = True
                    break

        if not is_resource_call:
            if (callee.getDeclaringClass().getName().startsWith(
                    "android.support.v") or callee.getDeclaringClass().getName().startsWith(
                    "androidx.")) and callee.getSubSignature().equals(self.sm_activity_find_view_by_id.getSubSignature()):
                is_resource_call = True

        if is_resource_call:
            if self.source_sink_config.getLayoutMatchingMode() == LayoutMatchingMode.MatchAll:
                return MethodSourceSinkDefinition.createReturnSource(CallType.MethodCall)

            control = self.get_layout_control(s_call_site, cfg)

            if control is not None:
                if self.source_sink_config.getLayoutMatchingMode() == LayoutMatchingMode.MatchSensitiveOnly \
                        and control.isSensitive():
                    return control.getSourceDefinition()

        return None

    def is_entry_point_method(self, method):
        return self.entry_point_utils.isEntryPointMethod(method)

    def get_sink_definition(self, s_call_site, manager: InfoflowManager, ap: AccessPath):
        definition = super().get_sink_definition(s_call_site, manager, ap)
        if definition is not None:
            return definition

        if s_call_site.containsInvokeExpr():
            callee = get_invoke_expr(s_call_site).method
            sub_sig = callee.getSubSignature()
            sc = callee.getDeclaringClass()
            is_param_tainted = False

            if ap is not None:
                if not sc.isInterface() and not ap.is_static_field_ref():
                    args = get_invoke_expr(s_call_site).args
                    for arg in args:
                        if arg == ap.value:
                            is_param_tainted = True
                            break

            if is_param_tainted or ap is None:
                for clazz in self.icc_base_classes:
                    if Scene.v().getOrMakeFastHierarchy().isSubclass(sc, clazz):
                        sm = clazz.getMethodUnsafe(sub_sig)
                        if sm is not None:
                            define = self.sink_methods[sm]
                            if define is not None:
                                return define
                            break

        return None

    def get_callback_definition(self, method):
        define = super().get_callback_definition(method)
        if isinstance(define, AndroidCallbackDefinition):
            d = define

            if d.getCallbackType() == CallbackType.Widge \
                    and self.source_sink_config.getLayoutMatchingMode() != LayoutMatchingMode.MatchAll:
                return None

            return define
