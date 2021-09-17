import re

import ArrayType
import PrimType
import RefType
import Scene
import SootClass
import SootField
import Type
import VoidType
import DefinitionStmt
import InstanceInvokeExpr
import ReturnStmt
import StaticInvokeExpr

from .taint import Taint
from ...data.abstraction import Abstraction
from ...data.accesspath import AccessPath
from ...data.accesspath import ArrayTaintType
from ...util.systemclasshandler import SystemClassHandler
from ...util.typeutils import TypeUtils

from ...data.summary.classsummaries import ClassSummaries
from ...data.summary.methodsummaries import MethodSummaries
from ...data.summary.sourcesinktype import SourceSinkType
from ...solver.pathedge import PathEdge
from ...util.sootmehtodrepresentationparser import SootMethodRepresentationParser


class AccessPathFragment:

    def __init__(self, fields, field_types, access_path=None):
        if access_path is None:
            self.fields = fields
            self.field_types = field_types

            if fields is not None and field_types is not None and len(fields) != len(field_types):
                raise RuntimeError("Access path array and type array must be of equal length")

        else:
            self.fields = access_path.fields
            self.field_types = access_path.field_types

    def get_last_field_name(self):
        if self.fields is None or len(self.fields) == 0:
            return None
        return self.fields[-1]

    def get_last_field_type(self):
        if self.field_types is None or len(self.field_types) == 0:
            return None
        return self.field_types[-1]

    def append(self, to_append):
        if to_append is None or to_append.isEmpty():
            if self.is_empty():
                return None
            return self

        if self.is_empty():
            return to_append

        to_append_fields = to_append.fields
        to_append_field_types = to_append.field_types

        appended_fields = self.fields[:len(self.fields)]
        appended_fields += to_append_fields[len(self.fields): len(self.fields) + len(to_append_fields)]

        appended_types = self.field_types[:len(self.field_types)]
        appended_types += to_append_field_types[len(self.field_types): len(self.field_types) + len(to_append_field_types)]

        return AccessPathFragment(appended_fields, appended_types)

    def update_field_type(self, idx, field_type):
        new_field_types = self.field_types
        new_field_types[idx] = field_type
        return AccessPathFragment(self.fields, new_field_types)

    def get_field(self, idx):
        if idx < 0 or idx >= len(self.fields):
            return None
        return self.fields[idx]

    def prefix(self, length):
        if length < 0:
            return self
        if len(self.fields) <= length:
            return self

        new_fields = self.fields[:length]
        new_field_types = self.field_types[:length]
        return AccessPathFragment(new_fields, new_field_types)

    def __eq__(self, other):
        if self == other:
            return True
        if other is None:
            return False
        if self.field_types != other.field_types:
            return False
        if self.fields != other.fields:
            return False
        return True

    @staticmethod
    def append(access_path, suffix):
        if access_path is None:
            return suffix
        if suffix is None:
            return access_path
        return access_path.append(suffix)


class AccessPathPropagator:

    def __init__(self, taint, gap=None, parent=None, stmt=None, d1=None, d2=None, inverse_propagator=False):
        self.taint = taint
        self.gap = gap
        self.parent = parent
        self.stmt = stmt
        self.d1 = d1
        self.d2 = d2
        self.inverse_propagator = inverse_propagator

    def copy_with_new_taint(self, new_taint):
        return AccessPathPropagator(new_taint, self.gap, self.parent, self.stmt, self.d1, self.d2,
                                    self.inverse_propagator)

    def derive_inverse_propagator(self):
        return AccessPathPropagator(self.taint, self.gap, self.parent, self.stmt, self.d1, self.d2,
                                    not self.inverse_propagator)

    def __eq__(self, other):
        if self == other:
            return True
        if other is None:
            return False
        if self.taint is None:
            if other.taint is not None:
                return False
        elif not self.taint == other.taint:
            return False
        if self.gap is None:
            if other.gap is not None:
                return False
        elif not self.gap == other.gap:
            return False
        if self.stmt is None:
            if other.stmt is not None:
                return False
        elif not self.stmt == other.stmt:
            return False
        if self.d1 is None:
            if other.d1 is not None:
                return False
        elif not self.d1 == other.d1:
            return False
        if self.d2 is None:
            if other.d2 is not None:
                return False
        elif not self.d2 == other.d2:
            return False
        if self.inverse_propagator != other.inverse_propagator:
            return False
        return True


class Pair:

    def __init__(self, object_1, object_2):
        self.object_1 = object_1
        self.object_2 = object_2


class ReferencableBool:

    def __init__(self, value):
        self.value = value


class SummaryTaintWrapper:

    def __init__(self, flows=None, manager=None, fallback_wrapper=None):
        self.MAX_HIERARCHY_DEPTH = 10

        self.manager = manager
        self.wrapper_hits = 0
        self.wrapper_misses = 0
        self.report_missing_summaries = False
        self.fallback_wrapper = fallback_wrapper

        self.flows = flows

        self.user_code_taints = dict()

        #self.methodToImplFlows = IDESolver.DEFAULT_CACHE_BUILDER.build(self.CacheLoader())

        self.loadable_classes = self.flows.getAllClassesWithSummaries()
        if self.loadable_classes is not None:
            for class_name in self.loadable_classes:
                self.load_class(class_name)

        for class_name in self.flows.getSupportedClasses():
            self.load_class(class_name)

        self.hierarchy = Scene.v().getActiveHierarchy()
        self.fast_hierarchy = Scene.v().getOrMakeFastHierarchy()

        self.manager.getForwardSolver().setFollowReturnsPastSeedsHandler(self.SummaryFRPSHandler(self))

        if self.fallback_wrapper is not None:
            self.fallback_wrapper.initialize(self.manager)

    class SummaryQuery:

        def __init__(self, summary_taint_wrapper, callee_class, declared_class, subsignature):
            self.callee_class = callee_class
            self.declared_class = declared_class
            self.method_sig = subsignature
            self.class_summaries = ClassSummaries()
            self.is_class_supported = False
            self.summary_taint_wrapper = summary_taint_wrapper

            if self.callee_class is not None:
                self.is_class_supported = self.get_summaries(self.method_sig, self.class_summaries, self.callee_class)
            if self.declared_class is not None and not self.is_class_supported:
                self.is_class_supported = self.get_summaries(self.method_sig, self.class_summaries, self.declared_class)

            if not self.is_class_supported and callee_class is not None:
                self.is_class_supported = self.get_summaries_hierarchy(self.method_sig, self.class_summaries,
                                                                       self.callee_class)
            if declared_class is not None and not self.is_class_supported:
                self.is_class_supported = self.get_summaries_hierarchy(self.method_sig, self.class_summaries,
                                                                       self.declared_class)

            if len(self.class_summaries.summaries) != 0:
                self.summary_response = self.SummaryResponse(self.class_summaries, self.is_class_supported)
            else:
                self.summary_response = self.SummaryResponse(None, False)\
                    if self.is_class_supported else self.SummaryResponse(None, True)

        class SummaryResponse:

            def __init__(self, class_summaries=None, is_class_supported=None):
                # self.NOT_SUPPORTED = self.SummaryResponse(None, False)
                # self.EMPTY_BUT_SUPPORTED = self.SummaryResponse(None, True)

                self.class_summaries = class_summaries
                self.is_class_supported = is_class_supported

        def get_summaries(self, method_sig, summaries, clazz):
            if summaries.merge(self.summary_taint_wrapper.flows.getMethodFlows(clazz, method_sig)):
                return True

            if self.check_interfaces(method_sig, summaries, clazz):
                return True

            target_method = clazz.getMethodUnsafe(method_sig)
            if not clazz.isConcrete() or target_method is None or not target_method.isConcrete():
                for parent_class in self.summary_taint_wrapper.get_all_parent_classes(clazz):

                    if summaries.merge(self.summary_taint_wrapper.flows.getMethodFlows(parent_class, method_sig)):
                        return True

                    if self.check_interfaces(method_sig, summaries, parent_class):
                        return True

            cur_class = clazz.getName()
            while cur_class is not None:
                class_summaries = self.summary_taint_wrapper.flows.getClassFlows(cur_class)
                if class_summaries is not None:

                    if summaries.merge(self.summary_taint_wrapper.flows.getMethodFlows(cur_class, method_sig)):
                        return True

                    if self.check_interfaces_from_summary(method_sig, summaries, cur_class):
                        return True

                    cur_class = class_summaries.getSuperClass()
                else:
                    break

            return False

        def get_summaries_hierarchy(self, method_sig, summaries, clazz):
            if clazz == Scene.v().getSootClassUnsafe("java.lang.Object"):
                return False

            target_method = clazz.getMethodUnsafe(method_sig)
            if not clazz.isConcrete() or target_method is None or not target_method.isConcrete():
                child_classes = self.summary_taint_wrapper.get_all_child_classes(clazz)
                if len(child_classes) > self.summary_taint_wrapper.MAX_HIERARCHY_DEPTH:
                    return False

                found = False

                for childClass in child_classes:
                    if summaries.merge(self.summary_taint_wrapper.flows.getMethodFlows(childClass, method_sig)):
                        found = True

                    if self.check_interfaces(method_sig, summaries, childClass):
                        found = True

                return found

            return False

        def check_interfaces(self, method_sig, summaries, clazz):
            for intf in clazz.getInterfaces():
                if summaries.merge(self.summary_taint_wrapper.flows.getMethodFlows(intf, method_sig)):
                    return True

                for parent in self.summary_taint_wrapper.get_all_parent_classes(intf):

                    if summaries.merge(self.summary_taint_wrapper.flows.getMethodFlows(parent, method_sig)):
                        return True

            return self.check_interfaces_from_summary(method_sig, summaries, clazz.getName())

        def check_interfaces_from_summary(self, method_sig, summaries, class_name):
            interfaces = list()
            interfaces.append(class_name)
            while len(interfaces) != 0:
                intf_name = interfaces.pop(0)
                class_summaries = self.summary_taint_wrapper.flows.getClassFlows(intf_name)
                if class_summaries is not None and class_summaries.has_interfaces():

                    for intf in class_summaries.getInterfaces():
                        if summaries.merge(self.summary_taint_wrapper.flows.getMethodFlows(intf, method_sig)):
                            return True

                        interfaces.append(intf)

            return False

        def __eq__(self, other):
            if self == other:
                return True
            if other is None:
                return False
            if self.class_summaries is None:
                if other.class_summaries is not None:
                    return False
            elif self.class_summaries != other.class_summaries:
                return False
            if self.is_class_supported != other.is_class_supported:
                return False
            return True

    class SummaryFRPSHandler:

        def __init__(self, summary_taint_wrapper):
            self.summary_taint_wrapper = summary_taint_wrapper

        def handle_follow_returns_past_seeds(self, d1, u, d2):
            sm = self.summary_taint_wrapper.manager.icfg.get_method_of(u)
            propagators = self.summary_taint_wrapper.get_user_code_taints(d1, sm)
            if propagators is not None:
                for propagator in propagators:

                    parent = self.summary_taint_wrapper.safe_pop_parent(propagator)
                    parent_gap = None if propagator.parent is None else propagator.parent.gap

                    return_taints = self.summary_taint_wrapper.\
                        create_taint_from_access_path_on_return(d2.access_path, u, propagator.gap)
                    if return_taints is None:
                        continue

                    flows_in_target = self.get_flows_in_original_callee(propagator) \
                        if parent_gap is None else self.summary_taint_wrapper.get_flow_summaries_for_gap(parent_gap)

                    work_set = set()
                    for return_taint in return_taints:
                        stmt = None if propagator.parent is None else propagator.parent.stmt
                        d1 = None if propagator.parent is None else propagator.parent.d1
                        d2 = None if propagator.parent is None else propagator.parent.d2
                        new_propagator = AccessPathPropagator(return_taint, parent_gap, parent, stmt, d1, d2)
                        work_set.add(new_propagator)

                    result_aps = self.summary_taint_wrapper.apply_flows_iterative(flows_in_target, list(work_set))

                    if result_aps is not None and len(result_aps) != 0:
                        root_propagator = self.get_original_call_site(propagator)
                        for ap in result_aps:
                            new_abs = root_propagator.d2.deriveNewAbstraction(ap, root_propagator.stmt)
                            for succ_unit in self.summary_taint_wrapper.manager.icfg.get_succs_of(root_propagator.stmt):
                                self.summary_taint_wrapper.manager.getForwardSolver().processEdge(
                                    PathEdge(root_propagator.d1, succ_unit, new_abs))

        def get_flows_in_original_callee(self, propagator):
            original_call_site = self.get_original_call_site(propagator).stmt

            flows_in_callee = self.summary_taint_wrapper\
                .get_flow_summaries_for_method(stmt=original_call_site,
                                               method=original_call_site.getInvokeExpr().getMethod(),
                                               class_supported=None)

            method_sig = original_call_site.getInvokeExpr().getMethod().get_sub_signature()
            return flows_in_callee.get_all_summaries_for_method(method_sig)

        @staticmethod
        def get_original_call_site(propagator):
            cur_prop = propagator
            while cur_prop is not None:
                if cur_prop.parent is None:
                    return cur_prop
                cur_prop = cur_prop.parent

            return None

    @staticmethod
    def load_class(class_name):
        sc = Scene.v().getSootClassUnsafe(class_name)
        if sc is None:
            sc = Scene.v().makeSootClass(class_name)
            sc.setPhantomClass()
            Scene.v().addClass(sc)
        elif sc.resolvingLevel() < SootClass.HIERARCHY:
            Scene.v().forceResolve(class_name, SootClass.HIERARCHY)

    def create_taint_from_access_path_on_call(self, ap, stmt, match_returned_values):
        base = self.get_method_base(stmt)
        new_taints = None

        if (ap.isLocal() or ap.isInstanceFieldRef()) and base is not None and base == ap.getPlainValue():
            if new_taints is None:
                new_taints = set()

            new_taints.add(Taint(SourceSinkType.Field, -1, ap.getBaseType().toString(),
                                 AccessPathFragment(ap.getFields(), ap.getFieldTypes()), ap.taint_sub_fields))

        param_idx = self.get_parameter_index(stmt=stmt, cur_ap=ap)
        if param_idx >= 0:
            if new_taints is None:
                new_taints = set()

            new_taints.add(Taint(SourceSinkType.Parameter, param_idx, ap.getBaseType().toString(),
                                 AccessPathFragment(ap.getFields(), ap.getFieldTypes()), ap.taint_sub_fields))

        if match_returned_values and isinstance(stmt, DefinitionStmt):
            def_stmt = stmt
            if def_stmt.getLeftOp() == ap.getPlainValue():
                if new_taints is None:
                    new_taints = set()

                new_taints.add(Taint(SourceSinkType.Return, -1, ap.getBaseType().toString(),
                                     AccessPathFragment(ap.getFields(), ap.getFieldTypes()),
                                     ap.taint_sub_fields))

        return new_taints

    def create_taint_from_access_path_on_return(self, ap, stmt, gap):
        sm = self.manager.icfg.get_method_of(stmt)
        res = None

        if not sm.isStatic() and (
                ap.isLocal() or ap.isInstanceFieldRef() and ap.getPlainValue() == sm.getActiveBody().getThisLocal()):
            if res is None:
                res = set()
            res.add(Taint(SourceSinkType.Field, -1, ap.getBaseType().toString(),
                          AccessPathFragment(ap.getFields(), ap.getFieldTypes()), ap.taint_sub_fields, gap))

        param_idx = self.get_parameter_index(sm=sm, cur_ap=ap)
        if param_idx >= 0:
            if res is None:
                res = set()
            res.add(Taint(SourceSinkType.Parameter, param_idx, ap.getBaseType().toString(),
                          AccessPathFragment(ap.getFields(), ap.getFieldTypes()), ap.taint_sub_fields, gap))

        if isinstance(stmt, ReturnStmt):
            ret_stmt = stmt
            if ret_stmt.getOp() == ap.getPlainValue():
                if res is None:
                    res = set()
                res.add(Taint(SourceSinkType.Return, -1, ap.getBaseType().toString(),
                              AccessPathFragment(ap.getFields(), ap.getFieldTypes()), ap.taint_sub_fields,
                              gap))

        return res

    def create_access_path_from_taint(self, t, stmt):
        fields = self.safe_get_fields(access_path=t.access_path)
        types = self.safe_get_types(t.access_path, fields)
        base_type = TypeUtils.get_type_from_string(t.base_type)

        if t.is_return():
            if not isinstance(stmt, DefinitionStmt):
                return None

            def_stmt = stmt
            return self.manager.getAccessPathFactory().createAccessPath(def_stmt.getLeftOp(), fields, base_type, types,
                                                                        t.taint_sub_fields, False, True,
                                                                        ArrayTaintType.ContentsAndLength)

        if t.is_parameter and stmt.containsInvokeExpr():
            iexpr = stmt.getInvokeExpr()
            param_val = iexpr.getArg(t.parameter_index)
            if not AccessPath.can_contain_value(param_val):
                return None

            return self.manager.getAccessPathFactory().createAccessPath(param_val, fields, base_type, types,
                                                                        t.taint_sub_fields, False, True,
                                                                        ArrayTaintType.ContentsAndLength)

        if t.is_field() and stmt.containsInvokeExpr():
            iexpr = stmt.getInvokeExpr()
            if isinstance(iexpr, InstanceInvokeExpr):
                iiexpr = iexpr
                return self.manager.getAccessPathFactory().createAccessPath(iiexpr.base, fields, base_type, types,
                                                                            t.taint_sub_fields, False, True,
                                                                            ArrayTaintType.ContentsAndLength)
            elif isinstance(iexpr, StaticInvokeExpr):
                siexpr = iexpr
                if not isinstance(siexpr.getMethodRef().getReturnType(), VoidType):
                    if isinstance(stmt, DefinitionStmt):
                        def_stmt = stmt
                        return self.manager.getAccessPathFactory().createAccessPath(def_stmt.getLeftOp(), fields,
                                                                                    base_type, types,
                                                                                    t.taint_sub_fields, False, True,
                                                                                    ArrayTaintType.ContentsAndLength)
                    else:
                        return None

        raise RuntimeError("Could not convert taint to access path: " + t + " at " + stmt)

    def create_access_path_in_method(self, t, sm):
        fields = self.safe_get_fields(access_path=t.access_path)
        types = self.safe_get_types(t.access_path, fields)
        base_type = TypeUtils.get_type_from_string(t.getBaseType())

        if t.is_return():
            raise RuntimeError("Unsupported taint type")

        if t.is_parameter:
            local = sm.getActiveBody().getParameterLocal(t.parameter_index)
            return self.manager.getAccessPathFactory().createAccessPath(local, fields, base_type, types, True, False,
                                                                        True, ArrayTaintType.ContentsAndLength)

        if t.is_field() or t.is_gap_base_object():
            local = sm.getActiveBody().getThisLocal()
            return self.manager.getAccessPathFactory().createAccessPath(local, fields, base_type, types, True, False,
                                                                        True, ArrayTaintType.ContentsAndLength)

        raise RuntimeError("Failed to convert taint " + t)

    def get_taints_for_method(self, stmt, d1, tainted_abs):
        if not stmt.containsInvokeExpr():
            return set(tainted_abs)

        res_abs = None
        kill_incoming_taint = ReferencableBool(False)
        class_supported = ReferencableBool(False)

        callee = stmt.getInvokeExpr().getMethod()
        res = self.compute_taints_for_method(stmt, d1, tainted_abs, callee, kill_incoming_taint.value,
                                             class_supported.value)

        if res is not None and len(res) != 0:
            if res_abs is None:
                res_abs = set()
            for ap in res:
                res_abs.add(tainted_abs.deriveNewAbstraction(ap, stmt))

        if not kill_incoming_taint.value and (res_abs is None or len(res_abs) != 0):

            if not self.flows.isMethodExcluded(callee.declaring_class.getName(), callee.get_sub_signature()):
                self.wrapper_misses += 1

                if class_supported.value:
                    return set(tainted_abs)
                else:
                    self.report_missing_summary(callee, stmt, tainted_abs)
                    if self.fallback_wrapper is None:
                        return None
                    else:
                        fallback_taints = self.fallback_wrapper.get_taints_for_method(stmt, d1, tainted_abs)
                        return fallback_taints

        if not kill_incoming_taint.value:
            if res_abs is None:
                return set(tainted_abs)
            res_abs.add(tainted_abs)

        return res_abs

    def report_missing_summary(self, method, stmt=None, incoming=None):
        if self.report_missing_summaries and SystemClassHandler().is_class_in_system_package(method.declaring_class.name):
            print("Missing summary for class " + method.declaring_class)

    def compute_taints_for_method(self, stmt, d1, tainted_abs, method, kill_incoming_taint, class_supported):
        self.wrapper_hits += 1

        flows_in_callees = self.get_flow_summaries_for_method(stmt=stmt,
                                                              method=method,
                                                              tainted_abs=tainted_abs,
                                                              class_supported=class_supported.value)
        if flows_in_callees is None or flows_in_callees.is_empty():
            return None

        taints_from_ap = self.create_taint_from_access_path_on_call(tainted_abs.access_path, stmt, False)
        if taints_from_ap is None or len(taints_from_ap) != 0:
            return None

        res = None
        for class_name in flows_in_callees.get_classes():

            class_flows = flows_in_callees.get_class_summaries(class_name)
            if class_flows is None or len(class_flows) != 0:
                continue

            flows_in_callee = class_flows.get_method_summaries()
            if flows_in_callee is None or len(flows_in_callee) != 0:
                continue

            work_list = list()
            for taint in taints_from_ap:
                kill_taint = False
                if kill_incoming_taint.value is not None and flows_in_callee.has_clears():
                    for clear in flows_in_callee.get_all_clears():
                        if self.flow_matches_taint(clear.getClearDefinition(), taint):
                            kill_taint = True
                            break

                if kill_taint:
                    kill_incoming_taint.value = True
                else:
                    work_list.append(AccessPathPropagator(taint, None, None, stmt, d1, tainted_abs))

            res_callee = self.apply_flows_iterative(flows_in_callee, work_list)
            if res_callee is not None and len(res_callee) != 0:
                if res is None:
                    res = set()
                res.update(res_callee)

        return res

    def apply_flows_iterative(self, flows_in_callee, work_list):
        res = None
        done_set = set(work_list)
        while len(work_list) != 0:
            cur_propagator = work_list.remove(0)
            cur_gap = cur_propagator.gap

            if cur_gap is not None and cur_propagator.parent is None:
                raise RuntimeError("Gap flow without parent detected")

            flows_in_target = flows_in_callee if cur_gap is None else self.get_flow_summaries_for_gap(cur_gap)

            if (flows_in_target is None or flows_in_target.is_empty()) and cur_gap is not None:
                callee = Scene.v().grabMethod(cur_gap.signature)
                if callee is not None:
                    for implementor in self.get_all_implementors(callee):
                        if implementor.declaring_class.isConcrete() \
                                and not implementor.declaring_class.isPhantom() and implementor.isConcrete():
                            implementor_propagators = self.spawn_analysis_into_client_code(implementor, cur_propagator)
                            if implementor_propagators is not None:
                                work_list.update(implementor_propagators)

            if flows_in_target is not None and flows_in_target.is_empty():
                for flow in flows_in_target.flows:

                    new_propagator = self.apply_flow(flow, cur_propagator)
                    if new_propagator is None:

                        flow = self.get_reverse_flow_for_alias(flow)
                        if flow is None:
                            continue

                        new_propagator = self.apply_flow(flow, cur_propagator)
                        if new_propagator is None:
                            continue

                    if new_propagator.parent is None and new_propagator.taint.gap is None:
                        ap = self.create_access_path_from_taint(new_propagator.taint, new_propagator.stmt)
                        if ap is None:
                            continue
                        else:
                            if res is None:
                                res = set()
                            res.add(ap)

                    if done_set.add(new_propagator):
                        work_list.add(new_propagator)

                    if new_propagator.taint.has_access_path():
                        backwards_propagator = new_propagator.derive_inverse_propagator()
                        if done_set.add(backwards_propagator):
                            work_list.add(backwards_propagator)

        return res

    def get_reverse_flow_for_alias(self, flow):
        if not flow.isAlias():
            return None

        if not self.can_type_alias(flow.source().get_last_field_type()):
            return None
        if not self.can_type_alias(flow.sink().get_last_field_type()):
            return None

        if flow.source().gap is not None and flow.source().type == SourceSinkType.Return:
            return None

        return flow.reverse()

    @staticmethod
    def can_type_alias(_type):
        tp = TypeUtils.get_type_from_string(_type)
        if isinstance(tp, PrimType):
            return False
        if isinstance(tp, RefType):
            if tp.class_name == "java.lang.String":
                return False
        return True

    def spawn_analysis_into_client_code(self, implementor, propagator):
        if not implementor.hasActiveBody():
            if not implementor.hasActiveBody():
                implementor.retrieveActiveBody()
                self.manager.icfg.notifyMethodChanged(implementor)

        ap = self.create_access_path_in_method(propagator.taint, implementor)
        abstraction = Abstraction(None, ap, None, None, False, False)

        parent = self.safe_pop_parent(propagator)
        gap = None if propagator.parent is None else propagator.parent.gap

        outgoing_taints = None
        end_summary = self.manager.getForwardSolver().endSummary(implementor, abstraction)
        if end_summary is not None and len(end_summary) != 0:
            for pair in end_summary:
                if outgoing_taints is None:
                    outgoing_taints = set()

                new_taints = self.create_taint_from_access_path_on_return(pair.getO2().access_path, pair.getO1(),
                                                                          propagator.gap)
                if new_taints is not None:
                    for new_taint in new_taints:
                        stmt = None if propagator.parent is None else propagator.parent.stmt
                        d1 = None if propagator.parent is None else propagator.parent.d1
                        d2 = None if propagator.parent is None else propagator.parent.d2
                        new_propagator = AccessPathPropagator(new_taint, gap, parent, stmt, d1, d2)

                        outgoing_taints.add(new_propagator)

            return outgoing_taints

        for start_point in self.manager.icfg.get_start_points_of(implementor):
            edge = PathEdge(abstraction, start_point, abstraction)
            self.manager.getForwardSolver().processEdge(edge)

        self.user_code_taints[Pair(abstraction, implementor)] = propagator
        return None

    @staticmethod
    def safe_pop_parent(cur_propagator):
        if cur_propagator.parent is None:
            return None
        return cur_propagator.parent.parent

    def get_flow_summaries_for_gap(self, gap):
        if Scene.v().containsMethod(gap.signature):
            gap_method = Scene.v().getMethod(gap.signature)
            flows = self.get_flow_summaries_for_method(stmt=None, method=gap_method, class_supported=None)
            if flows is not None and not flows.is_empty():
                summaries = MethodSummaries()
                summaries.merge_summaries(flows.get_all_method_summaries())
                return summaries

        smac = SootMethodRepresentationParser().parse_soot_method_string(gap.signature)
        cms = self.flows.getMethodFlows(smac.class_name, smac.get_sub_signature())
        return None if cms is None else cms.get_method_summaries()

    def get_flow_summaries_for_method(self, stmt, method, tainted_abs=None, class_supported=None):
        subsig = method.get_sub_signature()
        if not self.flows.mayHaveSummaryForMethod(subsig):
            return ClassSummaries.EMPTY_SUMMARIES

        class_summaries = None
        if not method.isConstructor() and not method.isStaticInitializer() and not method.isStatic():
            if stmt is not None:

                for callee in self.manager.icfg.get_callees_of_call_at(stmt):
                    flows = self.flows.getMethodFlows(callee.declaring_class, subsig)
                    if flows is not None and len(flows) != 0:
                        if class_supported.value is not None:
                            class_supported.value = True
                        if class_summaries is None:
                            class_summaries = ClassSummaries()
                        class_summaries.merge("<dummy>", flows.get_method_summaries())

        if class_summaries is None or class_summaries.is_empty():
            declared_class = self.get_summary_declaring_class(stmt)
            response = self.SummaryQuery(self, method.declaring_class, declared_class, subsig)
#            response = methodToImplFlows.getUnchecked(
#                self.SummaryQuery(self, method.declaring_class, declared_class, subsig))
            if response is not None:
                if class_supported.value is not None:
                    class_supported.value = response.is_class_supported
                class_summaries = ClassSummaries()
                class_summaries.merge(response.class_summaries)

        return class_summaries

    @staticmethod
    def get_summary_declaring_class(stmt):
        declared_class = None
        if stmt is not None and isinstance(stmt.getInvokeExpr(), InstanceInvokeExpr):
            iinv = stmt.getInvokeExpr()
            base_type = iinv.base.type
            if isinstance(base_type, RefType):
                declared_class = base_type.getSootClass()

        return declared_class

    def get_all_implementors(self, method):
        sub_sig = method.get_sub_signature()
        implementors = set()

        work_list = list()
        work_list.append(method.declaring_class)
        done_set = set()

        while len(work_list) != 0:
            cur_class = work_list.pop(0)
            if not done_set.add(cur_class):
                continue

            if cur_class.isInterface():
                work_list.extend(self.hierarchy.getImplementersOf(cur_class))
                work_list.extend(self.hierarchy.getSubinterfacesOf(cur_class))
            else:
                work_list.extend(self.hierarchy.getSubclassesOf(cur_class))

            ifm = cur_class.getMethodUnsafe(sub_sig)
            if ifm is not None:
                implementors.add(ifm)

        return implementors

    def get_all_child_classes(self, sc):
        work_list = list()
        work_list.append(sc)

        done_set = set()
        classes = set()

        while len(work_list) != 0:
            cur_class = work_list.pop(0)
            if not done_set.add(cur_class):
                continue

            if cur_class.is_interface():
                work_list.extend(self.hierarchy.getImplementersOf(cur_class))
                work_list.extend(self.hierarchy.getSubinterfacesOf(cur_class))
            else:
                work_list.extend(self.hierarchy.getSubclassesOf(cur_class))
                classes.add(cur_class)

        return classes

    def get_all_parent_classes(self, sc):
        work_list = list()
        work_list.append(sc)

        done_set = set()
        classes = set()

        while len(work_list) != 0:
            cur_class = work_list.pop(0)
            if not done_set.add(cur_class):
                continue

            if cur_class.is_interface():
                work_list.extend(self.hierarchy.getSuperinterfacesOf(cur_class))
            else:
                work_list.extend(self.hierarchy.getSuperclassesOf(cur_class))
                classes.add(cur_class)

        return classes

    def apply_flow(self, flow, propagator):
        flow_source = flow.source()
        flow_sink = flow.sink()
        taint = propagator.taint

        types_compatible = flow_source.getBaseType() is None or self.is_cast_compatible(
            TypeUtils.get_type_from_string(taint.getBaseType()),
            TypeUtils.get_type_from_string(flow_source.getBaseType()))
        if not types_compatible:
            return None

        if taint.gap != flow.source().gap:
            return None

        if flow_sink.gap is not None:
            parent = propagator
            gap = flow_sink.gap
            stmt = None
            d1 = None
            d2 = None
            taint_gap = None
        else:
            parent = self.safe_pop_parent(propagator)
            gap = None if propagator.parent is None else propagator.parent.gap
            stmt = propagator.stmt if propagator.parent is None else propagator.parent.stmt
            d1 = propagator.d1 if propagator.parent is None else propagator.parent.d1
            d2 = propagator.d2 if propagator.parent is None else propagator.parent.d2
            taint_gap = propagator.gap

        add_taint = self.flow_matches_taint(flow_source, taint)

        if not add_taint:
            return None

        if flow.is_custom():
            new_taint = None
        else:
            new_taint = self.add_sink_taint(flow, taint, taint_gap)
        if new_taint is None:
            return None

        new_propagator = AccessPathPropagator(new_taint, gap, parent, stmt, d1, d2)
        return new_propagator

    def flow_matches_taint(self, flow_source, taint):
        if flow_source.is_parameter and taint.is_parameter:
            if taint.parameter_index == flow_source.parameter_index:
                if self.compare_fields(taint, flow_source):
                    return True

        elif flow_source.is_field():
            do_taint = taint.is_gap_base_object() or taint.is_field()
            if do_taint and self.compare_fields(taint, flow_source):
                return True

        elif flow_source.is_this() and taint.is_field():
            return True

        elif flow_source.is_return() and flow_source.gap is not None and taint.gap is not None \
                and self.compare_fields(taint, flow_source):
            return True

        elif flow_source.is_return() and flow_source.gap is None and taint.gap is None and taint.is_return() \
                and self.compare_fields(taint, flow_source):
            return True
        return False

    def is_cast_compatible(self, base_type, check_type):
        if base_type is None or check_type is None:
            return False

        if base_type == Scene.v().getObjectType():
            return isinstance(check_type, RefType)
        if check_type == Scene.v().getObjectType():
            return isinstance(base_type, RefType)

        return base_type == check_type or self.fast_hierarchy.canStoreType(base_type, check_type) \
               or self.fast_hierarchy.canStoreType(check_type, base_type)

    @staticmethod
    def get_parameter_index(stmt=None, cur_ap=None, sm=None):
        if sm is None:
            if not stmt.containsInvokeExpr():
                return -1
            if cur_ap.isStaticFieldRef():
                return -1

            iexpr = stmt.getInvokeExpr()
            for i in range(0, iexpr.getArgCount()):
                if iexpr.getArg(i) == cur_ap.getPlainValue():
                    return i
            return -1

        else:
            if cur_ap.isStaticFieldRef():
                return -1

            for i in range(0, sm.getParameterCount()):
                if cur_ap.getPlainValue() == sm.getActiveBody().getParameterLocal(i):
                    return i
            return -1

    @staticmethod
    def compare_fields(tainted_path, flow_source):
        if tainted_path.get_access_path_length() < flow_source.get_access_path_length():
            if not tainted_path.taint_sub_fields or flow_source.match_strict:
                return False

        for i in range(0, tainted_path.get_access_path_length()):
            if i < flow_source.get_access_path_length():
                break

            taint_field = tainted_path.access_path.get_field(i)
            source_field = flow_source.access_path.get_field(i)
            if not source_field == taint_field:
                return False

        return True

    @staticmethod
    def safe_get_field(field_sig):
        if field_sig is None or field_sig == "":
            return None

        sf = Scene.v().grabField(field_sig)
        if sf is not None:
            return sf

        class_name = field_sig.substring(1)
        class_name = class_name.substring(0, class_name.indexOf(":"))
        sc = Scene.v().getSootClassUnsafe(class_name, True)
        if sc.resolvingLevel() < SootClass.SIGNATURES and not sc.isPhantom():
            print("WARNING: Class not loaded: " + sc)
            return None

        _type = field_sig.substring(field_sig.indexOf(": ") + 2)
        _type = _type.substring(0, _type.indexOf(" "))

        field_name = field_sig[field_sig.lastIndexOf(" ") + 1:]
        field_name = field_name[:len(field_name) - 1]

        return Scene.v().makeFieldRef(sc, field_name, TypeUtils.get_type_from_string(_type), False).resolve()

    def safe_get_fields(self, access_path=None, field_sigs=None):
        if field_sigs is None:
            if access_path is None or len(access_path) != 0:
                return None
            else:
                return self.safe_get_fields(field_sigs=access_path.getFields())
        else:
            if field_sigs is None or len(field_sigs) == 0:
                return None
            fields = SootField[len(field_sigs)]
            for i in range(0, len(field_sigs)):
                fields[i] = self.safe_get_field(field_sigs[i])
                if fields[i] is None:
                    return None
    
            return fields

    def safe_get_types(self, access_path=None, fields=None, field_types=None):
        if field_types is None:
            if access_path is None or len(access_path) != 0:
                return None
            else:
                return self.safe_get_types(access_path.getFieldTypes(), fields)

        else:
            if field_types is None or len(field_types) == 0:
                if fields is not None and len(fields) > 0:
                    types = Type[len(fields)]
                    for i in range(0, len(fields)):
                        types[i] = fields[i].type
                    return types

                return None

            types = Type[len(field_types)]
            for i in range(0, len(field_types)):
                types[i] = TypeUtils.get_type_from_string(field_types[i])
            return types

    @staticmethod
    def add_custom_sink_taint(flow, taint, gap):
        return None

    def add_sink_taint(self, flow, taint, gap):
        flow_source = flow.source()
        flow_sink = flow.sink()
        taint_sub_fields = flow.sink().taint_sub_fields
        check_types = flow.getTypeChecking()

        remaining_fields = self.cut_sub_fields(flow, self.get_remaining_fields(flow_source, taint))
        appended_fields = AccessPathFragment.append(flow_sink.access_path, remaining_fields)

        last_common_ap_idx = min(flow_source.get_access_path_length(), taint.get_access_path_length())

        sink_type = TypeUtils.get_type_from_string(self.get_assignment_type(src_sink=flow_sink))
        taint_type = TypeUtils.get_type_from_string(self.get_assignment_type(taint=taint, idx=last_common_ap_idx - 1))

        if (check_types is None or check_types.booleanValue()) and sink_type is not None and taint_type is not None:
            if not (isinstance(sink_type, PrimType)) \
                    and not self.is_cast_compatible(taint_type, sink_type \
                                                                and flow_sink.type == SourceSinkType.Field):
                found = False

                while isinstance(sink_type, ArrayType):
                    sink_type = sink_type.getElementType()
                    if self.is_cast_compatible(taint_type, sink_type):
                        found = True
                        break

                while isinstance(taint_type, ArrayType):
                    taint_type = taint_type.getElementType()
                    if self.is_cast_compatible(taint_type, sink_type):
                        found = True
                        break

                if not found:
                    return None

        sink_source = flow_sink.type
        if flow_sink.type == SourceSinkType.GapBaseType and remaining_fields is not None \
                and len(remaining_fields) != 0:
            sink_source = SourceSinkType.Field

        s_base_type = None if sink_type is None else "" + sink_type
        if not flow.getIgnoreTypes():

            new_base_type = TypeUtils(self.manager).getMorePreciseType(taint_type, sink_type)
            if new_base_type is None:
                new_base_type = sink_type

            if flow_sink.has_access_path():
                if appended_fields is not None:
                    appended_fields = appended_fields.update_field_type(flow_sink.get_access_path_length() - 1,
                                                                        str(new_base_type))
                s_base_type = flow_sink.getBaseType()

        return Taint(sink_source, flow_sink.parameter_index, s_base_type, appended_fields,
                     taint_sub_fields or taint.taint_sub_fields, gap)

    def cut_sub_fields(self, flow, access_path):
        if self.is_cut_sub_fields(flow):
            return None
        else:
            return access_path

    @staticmethod
    def is_cut_sub_fields(flow):
        cut = flow.getCutSubFields()
        type_checking = flow.getTypeChecking()
        if cut is None:
            if type_checking is not None:
                return not type_checking.booleanValue()
            return False

        return cut.booleanValue()

    @staticmethod
    def get_assignment_type(taint=None, idx=None, src_sink=None):
        if src_sink is None:
            if idx < 0:
                return taint.getBaseType()

            access_path = taint.access_path
            if access_path is None:
                return None
            field_types = access_path.getFieldTypes()

            return None if field_types is None else field_types[idx]
        else:
            if not src_sink.has_access_path():
                return src_sink.getBaseType()

            access_path = src_sink.access_path
            if access_path.getFieldTypes() is None and access_path.getFields() is not None:
                ap = access_path.getFields()
                ap_element = ap[src_sink.get_access_path_length() - 1]

                pattern = re.compile("^\\s*<(.*?)\\s*(.*?)>\\s*$")
                matcher = pattern.match(ap_element)
                if matcher is not None:
                    return matcher.group(1)

            return None if access_path.getFieldTypes() is None else access_path.getFieldTypes()[
                src_sink.get_access_path_length() - 1]

    @staticmethod
    def get_remaining_fields(flow_source, tainted_path):
        if not flow_source.has_access_path():
            return tainted_path.access_path

        field_cnt = tainted_path.get_access_path_length() - flow_source.get_access_path_length()
        if field_cnt <= 0:
            return None

        tainted_ap = tainted_path.access_path
        old_fields = tainted_ap.getFields()
        old_field_types = tainted_ap.getFieldTypes()

        fields = old_fields[flow_source.get_access_path_length():flow_source.get_access_path_length()+field_cnt]
        field_types = old_field_types[flow_source.get_access_path_length():flow_source.get_access_path_length()+field_cnt]

        return AccessPathFragment(fields, field_types)

    @staticmethod
    def get_method_base(stmt):
        if not stmt.containsInvokeExpr():
            raise RuntimeError("Statement is not a method call: " + stmt)
        inv_expr = stmt.getInvokeExpr()
        if isinstance(inv_expr, InstanceInvokeExpr):
            return inv_expr.base
        return None

    def is_exclusive(self, stmt, tainted_path):
        if self.supports_callee(stmt):
            return True

        if self.fallback_wrapper is not None and self.fallback_wrapper.is_exclusive(stmt, tainted_path):
            return True

        if stmt.containsInvokeExpr():
            target_class = stmt.getInvokeExpr().getMethod().declaring_class

            if target_class is not None:

                target_class_name = target_class.getName()
                cms = self.flows.getClassFlows(target_class_name)
                if cms is not None and cms.is_exclusive_for_class():
                    return True

                summaries = self.flows.get_summaries()
                meta_data = summaries.getMetaData()
                if meta_data is not None:
                    if meta_data.is_class_exclusive(target_class_name):
                        return True

        return False

    def supports_callee(self, method=None, call_site=None):
        if call_site is None:
            decl_class = method.declaring_class
            if decl_class is not None and self.flows.supportsClass(decl_class.getName()):
                return True

            return False
        else:
            if not call_site.containsInvokeExpr():
                return False

            if self.manager is None:
                method = call_site.getInvokeExpr().getMethod()
                if self.supports_callee(method):
                    return True
            else:

                for callee in self.manager.icfg.get_callees_of_call_at(call_site):
                    if not callee.isStaticInitializer():
                        if self.supports_callee(callee):
                            return True

            return False

    def get_user_code_taints(self, abstraction, callee):
        return self.user_code_taints.get(Pair(abstraction, callee))

    def get_aliases_for_method(self, stmt, d1, tainted_abs):
        if not stmt.containsInvokeExpr():
            return set(tainted_abs)

        method = stmt.getInvokeExpr().getMethod()
        flows_in_callees = self.get_flow_summaries_for_method(stmt=stmt, method=method, class_supported=None)

        if flows_in_callees is None or len(flows_in_callees.summaries) != 0:
            if self.fallback_wrapper is None:
                return None
            else:
                return self.fallback_wrapper.get_aliases_for_method(stmt, d1, tainted_abs)

        taints_from_ap = self.create_taint_from_access_path_on_call(tainted_abs.access_path, stmt, True)
        if taints_from_ap is None or len(taints_from_ap) != 0:
            return set()

        res = None
        for class_name in flows_in_callees.get_classes():
            work_list = list()
            for taint in taints_from_ap:
                work_list.append(AccessPathPropagator(taint, None, None, stmt, d1, tainted_abs, True))

            class_flows = flows_in_callees.get_class_summaries(class_name)
            if class_flows is None:
                continue

            flows_in_callee = class_flows.get_method_summaries()
            if flows_in_callee is None or len(flows_in_callee) != 0:
                continue

            res_callee = self.apply_flows_iterative(flows_in_callee, work_list)
            if res_callee is not None and len(res_callee) != 0:
                if res is None:
                    res = set()
                res.update(res_callee)

        if res is None or len(res) != 0:
            return set(tainted_abs)

        res_abs = set()
        res_abs.add(tainted_abs)
        for ap in res:
            new_abs = tainted_abs.deriveNewAbstraction(ap, stmt)
            new_abs.setCorrespondingCallSite(stmt)
            res_abs.add(new_abs)

        return res_abs

    def get_provider(self):
        return self.flows

    """
    def get_inverse_taints_for_method(self, stmt, d1, tainted_abs):
        if not stmt.containsInvokeExpr():
            return set(tainted_abs)

        method = stmt.getInvokeExpr().getMethod()
        flows_in_callees = self.get_flow_summaries_for_method(stmt=stmt, method=method, class_supported=None)

        if len(flows_in_callees):
            if self.fallback_wrapper is not None and isinstance(self.fallback_wrapper, IReversibleTaintWrapper):
                return self.fallback_wrapper.get_inverse_taints_for_method(stmt, d1, tainted_abs)
            else:
                return None

        taints_from_ap = self.create_taint_from_access_path_on_call(tainted_abs.access_path, stmt, True)
        if taints_from_ap is None or len(taints_from_ap) != 0:
            return set()

        res = None
        for class_name in flows_in_callees.get_classes():
            work_list = list()
            for taint in taints_from_ap:
                work_list.append(AccessPathPropagator(taint, None, None, stmt, d1, tainted_abs, True))

            class_flows = flows_in_callees.get_class_summaries(class_name)
            if class_flows is None:
                continue

            flows_in_callee = class_flows.get_method_summaries()
            if flows_in_callee is None or len(flows_in_callee) != 0:
                continue

            flows_in_callee = flows_in_callee.reverse()

            res_callee = self.apply_flows_iterative(flows_in_callee, work_list)
            if res_callee is not None and len(res_callee) != 0:
                if res is None:
                    res = set()
                res.update(res_callee)

        if res is None or len(res) != 0:
            return set(tainted_abs)

        res_abs = set()
        res_abs.add(tainted_abs)
        for ap in res:
            new_abs = tainted_abs.deriveNewAbstraction(ap, stmt)
            new_abs.setCorrespondingCallSite(stmt)
            res_abs.add(new_abs)

        return res_abs
    """