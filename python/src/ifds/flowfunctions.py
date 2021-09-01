import StaticFieldRef, StaticFieldTrackingMode, ArrayRef, FieldRef, InstanceFieldRef
import CastExpr, InstanceOfExpr, LengthExpr, NewArrayExpr, InstanceInvokeExpr
import Stmt, AssignStmt, ReturnStmt, DefinitionStmt
import TypeUtils, BooleanType, ArrayTaintType, RefType, NoneType, PrimType
import Collections
import Aliasing
import Local
import HashSet
import ByReferenceBoolean
import BaseSelector
import KillAll
import FlowFunctionType
import AccessPath
import Value
from .functions.solvernormalflowfunction import SolverNormalFlowFunction
from .functions.solvercallflowfunction import SolverCallFlowFunction
from .functions.solverreturnflowfuntion import SolverReturnFlowFunction
from .functions.solvercalltoreturnflowfunction import SolverCallToReturnFlowFunction
from .misc.copymember import copy_member
from infoflowproblems import InfoflowProblem


class FlowFunctions:

    def __init__(self, infoflow):
        copy_member(self, infoflow)

    class NotifyingNormalFlowFunction(SolverNormalFlowFunction):



    """
    def getNormalFlowFunction(self, curr, succ):
        pass

    def getCallFlowFunction(self, callStmt, destinationMethod):
        pass

    def getReturnFlowFunction(self, callSite, calleeMethod, exitStmt, returnSite):
        pass

    def getCallToReturnFlowFunction(self, callSite, returnSite):
        pass
    """

    def addTaintViaStmt(self, d1, assign_stmt, source, taint_set, cut_first_field, method, target_type):
        left_value = assign_stmt.getLeftOp()
        right_value = assign_stmt.getRightOp()

        if isinstance(left_value, StaticFieldRef) \
            and self.manager.getConfig().getStaticFieldTrackingMode() == StaticFieldTrackingMode._None:
            return

        new_abs = None
        if not source.getAccessPath().isEmpty():
            if isinstance(left_value, ArrayRef and target_type is not None):
                array_ref = left_value
                target_type = TypeUtils.buildArrayOrAddDimension(target_type, array_ref.getType().getArrayType())

            if isinstance(right_value, CastExpr):
                cast = assign_stmt.getRightOp()
                target_type = cast.getType()
            elif isinstance(right_value, InstanceOfExpr):
                new_abs = source.deriveNewAbstraction(self.manager.getAccessPathFactory().createAccessPath(
                    left_value, BooleanType.v(), True, ArrayTaintType.ContentsAndLength), assign_stmt)
        else:
            assert target_type is None

        array_taint_type = source.getAccessPath().getArrayTaintType()
        if isinstance(left_value, ArrayRef) and self.manager.getConfig().getEnableArraySizeTainting():
            array_taint_type = ArrayTaintType.Contents

        if new_abs is None:
            if source.getAccessPath().isEmpty():
                new_abs = source.deriveNewAbstraction(
                        self.manager.getAccessPathFactory().createAccessPath(left_value, True), assign_stmt, True)
            else:
                ap = self.manager.getAccessPathFactory().copyWithNewValue(source.getAccessPath(),
                                                                                    left_value,
                                                                                    target_type,
                                                                                    cut_first_field,
                                                                                    True,
                                                                                    array_taint_type)
                new_abs = source.deriveNewAbstraction(ap, assign_stmt)

        if new_abs is not None:
            if isinstance(left_value, StaticFieldRef) \
                and self.manager.getConfig().getStaticFieldTrackingMode() == StaticFieldTrackingMode.ContextFlowInsensitive:
                self.manager.getGlobalTaintManager().addToGlobalTaintState(new_abs)
            else:
                taint_set.add(new_abs)
                aliasing = self.manager.getAliasing()
                if aliasing is not None and aliasing.canHaveAliases(assign_stmt, left_value, new_abs):
                    aliasing.computeAliases(d1, assign_stmt, left_value, taint_set, method, new_abs)

    def has_valid_callees(self, call):
        callees = self.interprocedural_cfg().getCalleesOfCallAt(call)

        for callee in callees:
            if callee.isConcrete():
                return True
        return False

    def create_new_taint_on_assignment(self, assign_stmt, right_vals, d1, new_source):
        left_value = assign_stmt.getLeftOp()
        right_value = assign_stmt.getRightOp()
        add_left_value = False

        if isinstance(right_value, LengthExpr):
            return Collections.singleton(new_source)


        implicit_taint = new_source.getTopPostdominator() is not None \
                        and new_source.getTopPostdominator().getUnit() is not None
        implicit_taint |= new_source.getAccessPath().isEmpty()

        if implicit_taint:
            if d1 is None or d1.getAccessPath().isEmpty() and not isinstance(left_value, FieldRef):
                return Collections.singleton(new_source)

            if new_source.getAccessPath().isEmpty():
                add_left_value = True

        alias_overwritten = not add_left_value \
                           and not new_source.isAbstractionActive() \
                           and Aliasing.baseMatchesStrict(right_value, new_source) \
                           and isinstance(right_value.getType(), RefType) \
                           and not new_source.dependsOnCutAP()

        aliasing = self.manager.getAliasing()
        if aliasing is None:
            return None

        cut_first_field = False
        mapped_ap = new_source.getAccessPath()
        target_type = None
        if not add_left_value and not alias_overwritten:
            for rightVal in right_vals:
                if isinstance(rightVal, FieldRef):
                    right_ref = rightVal
                    if isinstance(right_ref, InstanceFieldRef) \
                            and isinstance(right_ref.getBase().getType(), NoneType):
                        return None

                    mapped_ap = aliasing.mayAlias(new_source.getAccessPath(), right_ref)

                    if isinstance(rightVal, StaticFieldRef):
                        if self.manager.getConfig().getStaticFieldTrackingMode() is not StaticFieldTrackingMode._None \
                                and mapped_ap is not None:
                            add_left_value = True
                            cut_first_field = True
                    elif isinstance(rightVal, InstanceFieldRef):
                        right_base = right_ref.getBase()
                        source_base = new_source.getAccessPath().getPlainValue()
                        right_field = right_ref.getField()

                        if mapped_ap is not None:
                            add_left_value = True
                            cut_first_field = (mapped_ap.getFieldCount() > 0
                                    and mapped_ap.getFirstField() == right_field)
                        elif (aliasing.mayAlias(right_base, source_base)
                              and new_source.getAccessPath().getFieldCount() == 0
                              and new_source.getAccessPath().getTaintSubFields()):
                            add_left_value = True
                            target_type = right_field.getType()
                            if (mapped_ap is None):
                                mapped_ap = self.manager.getAccessPathFactory().createAccessPath(right_base, True)
                elif isinstance(rightVal, Local) and new_source.getAccessPath().isInstanceFieldRef():
                    base = new_source.getAccessPath().getPlainValue()
                    if aliasing.mayAlias(rightVal, base):
                        add_left_value = True
                        target_type = new_source.getAccessPath().getBaseType()
                elif aliasing.mayAlias(rightVal, new_source.getAccessPath().getPlainValue()):
                    if not isinstance(assign_stmt.getRightOp(), NewArrayExpr):
                        if self.manager.getConfig().getEnableArraySizeTainting() \
                                or not isinstance(right_value, NewArrayExpr):
                            add_left_value = True
                            target_type = new_source.getAccessPath().getBaseType()

                if add_left_value:
                    break

        if not add_left_value:
            return None

        if not new_source.isAbstractionActive() \
                and isinstance(assign_stmt.getLeftOp().getType(), PrimType) \
                or TypeUtils.isStringType(assign_stmt.getLeftOp().getType()) \
                and not new_source.getAccessPath().getCanHaveImmutableAliases():
            return Collections.singleton(new_source)

        res = HashSet()
        target_ab = new_source if mapped_ap.equals(new_source.getAccessPath()) \
            else new_source.deriveNewAbstraction(mapped_ap, None)
        self.addTaintViaStmt(d1, assign_stmt, target_ab, res, cut_first_field,
                              self.interprocedural_cfg().get_method_of(assign_stmt), target_type)
        res.add(new_source)
        return res

    def get_normal_flow_function(self, src, dest):
        if not isinstance(src, Stmt):
            return self.KillAll.v()

        return self.NotifyingNormalFlowFunction(self, src, dest)

    def get_call_flow_function(self, src, dest):
        if not dest.isConcrete():
            #logger.debug("Call skipped because target has no body::} ->:}", src, dest)
            return KillAll.v()

        stmt = src
        ie = stmt.getInvokeExpr() if stmt is not None and stmt.containsInvokeExpr() else None

        paramLocals = dest.getActiveBody().getParameterLocals().toArray(Local[0])

        thisLocal = None if dest.isStatic() else dest.getActiveBody().getThisLocal()

        aliasing = self.manager.getAliasing()
        if aliasing is None:
            return KillAll.v()

        return SolverCallFlowFunction(self)

    def get_return_flow_function(self, callSite, callee, exitStmt, retSite):
        if callSite is not None and not isinstance(callSite, Stmt):
            return KillAll.v()
        iCallStmt = callSite
        isReflectiveCallSite = callSite is not None \
                               and self.interprocedural_cfg().isReflectiveCallSite(callSite)

        returnStmt = exitStmt if isinstance(exitStmt, ReturnStmt) else None

        paramLocals = callee.getActiveBody().getParameterLocals().toArray(Local[0])

        aliasing = self.manager.getAliasing()
        if (aliasing is None):
            return KillAll.v()

        thisLocal = None if callee.isStatic() else callee.getActiveBody().getThisLocal()

        return SolverReturnFlowFunction(self)

    def get_call_to_return_flow_function(self, call, returnSite):
        if not isinstance(call, Stmt):
            return KillAll.v()

        iCallStmt = call
        invExpr = iCallStmt.getInvokeExpr()

        aliasing = self.manager.getAliasing()
        if aliasing is None:
            return KillAll.v()

        callArgs = Value[invExpr.getArgCount()]
        for i in range(invExpr.getArgCount()):
            callArgs[i] = invExpr.getArg(i)

        isSink = self.manager.getSourceSinkManager().getSinkInfo(iCallStmt, self.manager, None) is not None \
            if (self.manager.getSourceSinkManager() is not None) \
            else False
        isSource = self.manager.getSourceSinkManager().getSourceInfo(iCallStmt, self.manager) is not None \
            if self.manager.getSourceSinkManager() is not None \
            else False

        callee = invExpr.getMethod()
        hasValidCallees = self.has_valid_callees( call )

        return SolverCallToReturnFlowFunction()

    def map_access_path_to_callee(self, callee, ie, paramLocals, thisLocal, ap):
        if ap.isEmpty():
            return None

        isExecutorExecute = self.interprocedural_cfg().isExecutorExecute(ie, callee)

        res = None

        aliasing = self.manager.getAliasing()
        if aliasing is None:
            return None

        if aliasing.getAliasingStrategy().isLazyAnalysis() and Aliasing.canHaveAliases(ap):
            res = HashSet()
            res.add(ap)

        baseLocal = None
        if not isExecutorExecute \
                and not ap.isStaticFieldRef() \
                and not callee.isStatic():
            if self.interprocedural_cfg().isReflectiveCallSite(ie):
                baseLocal = ie.getArg(0)
            else:
                assert isinstance(ie, InstanceInvokeExpr)
                vie = ie
                baseLocal = vie.getBase()

        if baseLocal is not None:
            if aliasing.mayAlias(baseLocal, ap.getPlainValue()):
                if self.manager.getTypeUtils().hasCompatibleTypesForCall(ap, callee.getDeclaringClass()):
                    if res is None:
                        res = HashSet()

                    if thisLocal is None:
                        thisLocal = callee.getActiveBody().getThisLocal()

                    res.add(self.manager.getAccessPathFactory().copyWithNewValue(ap, thisLocal))

        if isExecutorExecute:
            if aliasing.mayAlias(ie.getArg(0), ap.getPlainValue()):
                if res is None:
                    res = HashSet()
                res.add(self.manager.getAccessPathFactory().copyWithNewValue(ap, callee.getActiveBody().getThisLocal()))
        elif callee.getParameterCount() > 0:
            isReflectiveCallSite = self.interprocedural_cfg().isReflectiveCallSite(ie)

            for i in range(1 if isReflectiveCallSite else 0, ie.getArgCount()):
                if aliasing.mayAlias(ie.getArg(i), ap.getPlainValue()):
                    if res is None:
                        res = HashSet()

                    if paramLocals is None:
                        paramLocals = callee.getActiveBody().getParameterLocals().toArray(Local[callee.getParameterCount()])

                    if isReflectiveCallSite:
                        for j in range(paramLocals.length):
                            newAP = self.manager.getAccessPathFactory().copyWithNewValue(ap, paramLocals[j], None, False)
                            if newAP is not None:
                                res.add(newAP)
                    else:
                        newAP = self.manager.getAccessPathFactory().copyWithNewValue(ap, paramLocals[i])
                        if newAP is not None:
                            res.add(newAP)
        return res
