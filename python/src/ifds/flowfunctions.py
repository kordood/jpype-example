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
from infoflowproblems import InfoflowProblem


class FlowFunctions:

    def __init__(self, infoflow):
        self.infoflow = infoflow

    class NotifyingNormalFlowFunction(SolverNormalFlowFunction):

        def __init__(self, flowfunctions, stmt, dest):
            self.stmt = stmt
            self.dest = dest
            self.flowfunctions = flowfunctions
            super().__init__()

        def compute_targets(self, d1, source):
            if self.flowfunctions.taint_propagation_handler is not None:
                self.flowfunctions.taint_propagation_handler.notifyFlowIn(self.stmt, source,
                                                                          self.flowfunctions.infoflow.manager,
                                                                          FlowFunctionType.NormalFlowFunction)

            res = self.compute_targets_internal(d1, source)
            return self.flowfunctions.infoflow.notify_out_flow_handlers(self.stmt, d1, source, res,
                                                                        FlowFunctionType.NormalFlowFunction)

        def compute_targets_internal(self, d1, source):
            new_source = None
            if not source.isAbstractionActive() and self.flowfunctions.src == source.getActivationUnit():
                new_source = source.getActiveCopy()
            else:
                new_source = source

            kill_source = ByReferenceBoolean()
            kill_all = ByReferenceBoolean()
            res = self.flowfunctions.infoflow.propagationRules.applyNormalFlowFunction(d1, new_source, self.stmt,
                                                                                       self.flowfunctions.dest, kill_source, kill_all)
            if kill_all.value:
                return Collections.emptySet()

            if isinstance(self.flowfunctions.src, AssignStmt):
                assign_stmt = self.flowfunctions.src
                right = assign_stmt.getRightOp()
                right_vals = BaseSelector.selectBaseList(right, True)

                res_assign = self.flowfunctions.createNewTaintOnAssignment(assign_stmt, right_vals, d1, new_source)
                if res_assign is not None and not res_assign.isEmpty():
                    if res is not None:
                        res.addAll(res_assign)
                        return res
                    else:
                        res = res_assign

            return Collections.emptySet() if res is None or res.isEmpty() else res

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
            and self.infoflow.manager.getConfig().getStaticFieldTrackingMode() == StaticFieldTrackingMode._None:
            return

        new_abs = None
        if not source.getAccessPath().isEmpty():
            if isinstance( left_value, ArrayRef and target_type is not None ):
                array_ref = left_value
                target_type = TypeUtils.buildArrayOrAddDimension( target_type, array_ref.getType().getArrayType() )

            if isinstance(right_value, CastExpr):
                cast = assign_stmt.getRightOp()
                target_type = cast.getType()
            elif isinstance(right_value, InstanceOfExpr):
                new_abs = source.deriveNewAbstraction(self.infoflow.manager.getAccessPathFactory().createAccessPath(
                    left_value, BooleanType.v(), True, ArrayTaintType.ContentsAndLength), assign_stmt)
        else:
            assert target_type is None

        array_taint_type = source.getAccessPath().getArrayTaintType()
        if isinstance(left_value, ArrayRef) and self.infoflow.manager.getConfig().getEnableArraySizeTainting():
            array_taint_type = ArrayTaintType.Contents

        if new_abs is None:
            if source.getAccessPath().isEmpty():
                new_abs = source.deriveNewAbstraction(
                        self.infoflow.manager.getAccessPathFactory().createAccessPath(left_value, True), assign_stmt, True)
            else:
                ap = self.infoflow.manager.getAccessPathFactory().copyWithNewValue( source.getAccessPath(),
                                                                                    left_value,
                                                                                    target_type,
                                                                                    cut_first_field,
                                                                                    True,
                                                                                    array_taint_type )
                new_abs = source.deriveNewAbstraction( ap, assign_stmt )

        if new_abs is not None:
            if isinstance(left_value, StaticFieldRef) \
                and self.infoflow.manager.getConfig().getStaticFieldTrackingMode() == StaticFieldTrackingMode.ContextFlowInsensitive:
                self.infoflow.manager.getGlobalTaintManager().addToGlobalTaintState(new_abs)
            else:
                taint_set.add( new_abs )
                aliasing = self.infoflow.manager.getAliasing()
                if aliasing is not None and aliasing.canHaveAliases( assign_stmt, left_value, new_abs ):
                    aliasing.computeAliases( d1, assign_stmt, left_value, taint_set, method, new_abs )

    def hasValidCallees(self, call):
        callees = self.infoflow.interprocedural_cfg().getCalleesOfCallAt(call)

        for callee in callees:
            if callee.isConcrete():
                return True
        return False

    def createNewTaintOnAssignment(self, assign_stmt, right_vals, d1, new_source):
        left_value = assign_stmt.getLeftOp()
        right_value = assign_stmt.getRightOp()
        add_left_value = False

        if isinstance(right_value, LengthExpr):
            return Collections.singleton( new_source )


        implicit_taint = new_source.getTopPostdominator() is not None \
                        and new_source.getTopPostdominator().getUnit() is not None
        implicit_taint |= new_source.getAccessPath().isEmpty()

        if implicit_taint:
            if d1 is None or d1.getAccessPath().isEmpty() and not isinstance(left_value, FieldRef):
                return Collections.singleton( new_source )

            if new_source.getAccessPath().isEmpty():
                add_left_value = True

        alias_overwritten = not add_left_value \
                           and not new_source.isAbstractionActive() \
                           and Aliasing.baseMatchesStrict( right_value, new_source ) \
                           and isinstance(right_value.getType(), RefType) \
                           and not new_source.dependsOnCutAP()

        aliasing = self.infoflow.manager.getAliasing()
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

                    mapped_ap = aliasing.mayAlias( new_source.getAccessPath(), right_ref )

                    if isinstance(rightVal, StaticFieldRef):
                        if self.infoflow.manager.getConfig().getStaticFieldTrackingMode() is not StaticFieldTrackingMode._None \
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
                                mapped_ap = self.infoflow.manager.getAccessPathFactory().createAccessPath(right_base, True)
                elif isinstance(rightVal, Local) and new_source.getAccessPath().isInstanceFieldRef():
                    base = new_source.getAccessPath().getPlainValue()
                    if aliasing.mayAlias(rightVal, base):
                        add_left_value = True
                        target_type = new_source.getAccessPath().getBaseType()
                elif aliasing.mayAlias( rightVal, new_source.getAccessPath().getPlainValue() ):
                    if not isinstance( assign_stmt.getRightOp(), NewArrayExpr ):
                        if self.infoflow.manager.getConfig().getEnableArraySizeTainting() \
                                or not isinstance(right_value, NewArrayExpr):
                            add_left_value = True
                            target_type = new_source.getAccessPath().getBaseType()

                if add_left_value:
                    break

        if not add_left_value:
            return None

        if not new_source.isAbstractionActive() \
                and isinstance( assign_stmt.getLeftOp().getType(), PrimType ) \
                or TypeUtils.isStringType( assign_stmt.getLeftOp().getType() ) \
                and not new_source.getAccessPath().getCanHaveImmutableAliases():
            return Collections.singleton( new_source )

        res = HashSet()
        target_ab = new_source if mapped_ap.equals( new_source.getAccessPath() ) \
            else new_source.deriveNewAbstraction( mapped_ap, None )
        self.addTaintViaStmt( d1, assign_stmt, target_ab, res, cut_first_field,
                              self.infoflow.interprocedural_cfg().get_method_of( assign_stmt ), target_type )
        res.add( new_source )
        return res

    def getNormalFlowFunction(self, src, dest):
        if not isinstance(src, Stmt):
            return self.infoflow.KillAll.v()

        return self.NotifyingNormalFlowFunction(self, src, dest)

    def getCallFlowFunction(self, src, dest):
        if not dest.isConcrete():
            #logger.debug("Call skipped because target has no body::} ->:}", src, dest)
            return KillAll.v()

        stmt = src
        ie = stmt.getInvokeExpr() if stmt is not None and stmt.containsInvokeExpr() else None

        paramLocals = dest.getActiveBody().getParameterLocals().toArray(Local[0])

        thisLocal = None if dest.isStatic() else dest.getActiveBody().getThisLocal()

        aliasing = self.infoflow.manager.getAliasing()
        if aliasing is None:
            return KillAll.v()

        return SolverCallFlowFunction(self)

    def getReturnFlowFunction(self, callSite, callee, exitStmt, retSite):
        if callSite is not None and not isinstance(callSite, Stmt):
            return KillAll.v()
        iCallStmt = callSite
        isReflectiveCallSite = callSite is not None \
                               and self.infoflow.interprocedural_cfg().isReflectiveCallSite(callSite)

        returnStmt = exitStmt if isinstance(exitStmt, ReturnStmt) else None

        paramLocals = callee.getActiveBody().getParameterLocals().toArray(Local[0])

        aliasing = self.infoflow.manager.getAliasing()
        if (aliasing is None):
            return KillAll.v()

        thisLocal = None if callee.isStatic() else callee.getActiveBody().getThisLocal()

        return self.SolverReturnFlowFunction()

    class SolverReturnFlowFunction():

        def computeTargets(self, source, d1, callerD1s):
            res = self.computeTargetsInternal(source, callerD1s)
            return self.notify_out_flow_handlers(self.exitStmt, d1, source, res, FlowFunctionType.ReturnFlowFunction)

        def computeTargetsInternal(self, source, callerD1s):
            if self.infoflow.manager.getConfig().getStopAfterFirstFlow() and not self.results.isEmpty():
                return None
            if source == self.getZeroValue():
                return None

            if self.taint_propagation_handler is not None:
                self.taint_propagation_handler.notifyFlowIn(self.exitStmt, source, self.infoflow.manager, FlowFunctionType.ReturnFlowFunction)
            callerD1sConditional = False
            for d1 in callerD1s:
                if d1.getAccessPath().isEmpty():
                    callerD1sConditional = True
                    break
            newSource = source
            if not source.isAbstractionActive():
                if self.callSite is not None:
                    if self.callSite == source.getActivationUnit() \
                            or self.isCallSiteActivatingTaint(self.callSite, source.getActivationUnit()):
                        newSource = source.getActiveCopy()

            if not newSource.isAbstractionActive() and newSource.getActivationUnit() is not None:
                if self.interproceduralCFG().get_method_of(newSource.getActivationUnit()) == self.callee:
                    return None

            killAll = ByReferenceBoolean()
            res = self.propagationRules.applyReturnFlowFunction(callerD1s, newSource, self.exitStmt, self.retSite,
                                                                self.callSite, killAll)
            if killAll.value:
                return None
            if res is None:
                res = HashSet()

            if self.callSite is None:
                return None

            if self.aliasing.getAliasingStrategy().isLazyAnalysis() \
                    and Aliasing.canHaveAliases(newSource.getAccessPath()):
                res.add(newSource)

            if not newSource.getAccessPath().isStaticFieldRef() and not self.callee.isStaticInitializer():
                if self.returnStmt is not None and isinstance(self.callSite, DefinitionStmt):
                    retLocal = self.returnStmt.getOp()
                    defnStmt = self.callSite
                    leftOp = defnStmt.getLeftOp()

                    if self.aliasing.mayAlias(retLocal, newSource.getAccessPath().getPlainValue()) \
                            and not self.isExceptionHandler(self.retSite):
                        ap = self.infoflow.manager.getAccessPathFactory().copyWithNewValue(newSource.getAccessPath(), leftOp)
                        abs = newSource.deriveNewAbstraction(ap, self.exitStmt)
                        if abs is not None:
                            res.add(abs)
                            if self.aliasing.getAliasingStrategy().requiresAnalysisOnReturn():
                                for d1 in callerD1s:
                                    self.aliasing.computeAliases(d1, self.iCallStmt, leftOp, res,
                                                                  self.interproceduralCFG().get_method_of(self.callSite), abs)

                sourceBase = newSource.getAccessPath().getPlainValue()
                parameterAliases = False
                originalCallArg = None
                for i in range(self.callee.getParameterCount()):
                    if isinstance(self.callSite, DefinitionStmt) and not self.isExceptionHandler(self.retSite):
                        defnStmt = self.callSite
                        leftOp = defnStmt.getLeftOp()
                        originalCallArg = defnStmt.getInvokeExpr().getArg(i)
                        if originalCallArg == leftOp:
                            continue

                    if self.aliasing.mayAlias(self.paramLocals[i], sourceBase):
                        parameterAliases = True
                        originalCallArg = self.iCallStmt.getInvokeExpr().getArg(1 if self.isReflectiveCallSite else i)

                        if not AccessPath.canContainValue(originalCallArg):
                            continue
                        if not self.isReflectiveCallSite \
                                and not self.infoflow.manager.getTypeUtils().checkCast(source.getAccessPath(),
                                                                         originalCallArg.getType()):
                            continue

                        if isinstance(source.getAccessPath().getBaseType(), PrimType):
                            continue
                        if TypeUtils.isStringType(source.getAccessPath().getBaseType()) \
                                and not source.getAccessPath().getCanHaveImmutableAliases():
                            continue

                        if not source.getAccessPath().getTaintSubFields():
                            continue

                        if self.interproceduralCFG().methodWritesValue(self.callee, self.paramLocals[i]):
                            continue

                        ap = self.infoflow.manager.getAccessPathFactory().copyWithNewValue(
                                newSource.getAccessPath(), originalCallArg,
                                None if self.isReflectiveCallSite else newSource.getAccessPath().getBaseType(),
                                False)
                        abs = newSource.deriveNewAbstraction(ap, self.exitStmt)

                        if abs is not None:
                            res.add(abs)

                thisAliases = False
                if isinstance(self.callSite, DefinitionStmt) and not self.isExceptionHandler(self.retSite):
                    defnStmt = self.callSite
                    leftOp = defnStmt.getLeftOp()
                    if self.thisLocal == leftOp:
                        thisAliases = True

                if not parameterAliases and not thisAliases and source.getAccessPath().getTaintSubFields() \
                        and isinstance(self.iCallStmt.getInvokeExpr(), InstanceInvokeExpr) \
                        and self.aliasing.mayAlias(self.thisLocal, sourceBase):

                    if self.infoflow.manager.getTypeUtils().checkCast(source.getAccessPath(), self.thisLocal.getType()):
                        iIExpr = self.iCallStmt.getInvokeExpr()

                        callerBaseLocal = iIExpr.getArg(0)\
                            if self.interproceduralCFG().isReflectiveCallSite(iIExpr) else iIExpr.getBase()
                        ap = self.infoflow.manager.getAccessPathFactory().copyWithNewValue(
                                newSource.getAccessPath(), callerBaseLocal,
                                None if self.isReflectiveCallSite else newSource.getAccessPath().getBaseType(),
                                False)
                        abs = newSource.deriveNewAbstraction(ap, self.exitStmt)
                        if abs is not None:
                            res.add(abs)

            for abs in res:
                if abs.isImplicit() and not callerD1sConditional \
                        or self.aliasing.getAliasingStrategy().requiresAnalysisOnReturn():
                    for d1 in callerD1s:
                        self.aliasing.computeAliases(d1, self.iCallStmt, None, res,
                                                      self.interproceduralCFG().get_method_of(self.callSite), abs)

                if abs != newSource:
                    abs.setCorrespondingCallSite(self.iCallStmt)
            return res

    def getCallToReturnFlowFunction(self, call, returnSite):
        if not isinstance(call, Stmt):
            return KillAll.v()

        iCallStmt = call
        invExpr = iCallStmt.getInvokeExpr()

        aliasing = self.infoflow.manager.getAliasing()
        if aliasing is None:
            return KillAll.v()

        callArgs = Value[invExpr.getArgCount()]
        for i in range(invExpr.getArgCount()):
            callArgs[i] = invExpr.getArg(i)

        isSink = self.infoflow.manager.getSourceSinkManager().getSinkInfo(iCallStmt, self.infoflow.manager, None) is not None \
            if (self.infoflow.manager.getSourceSinkManager() is not None) \
            else False
        isSource = self.infoflow.manager.getSourceSinkManager().getSourceInfo(iCallStmt, self.infoflow.manager) is not None \
            if self.infoflow.manager.getSourceSinkManager() is not None \
            else False

        callee = invExpr.getMethod()
        hasValidCallees = self.hasValidCallees(call)

        return SolverCallToReturnFlowFunction()

    def mapAccessPathToCallee(self, callee, ie, paramLocals, thisLocal, ap):
        if ap.isEmpty():
            return None

        isExecutorExecute = self.interproceduralCFG().isExecutorExecute(ie, callee)

        res = None

        aliasing = self.infoflow.manager.getAliasing()
        if aliasing is None:
            return None

        if aliasing.getAliasingStrategy().isLazyAnalysis() and Aliasing.canHaveAliases(ap):
            res = HashSet()
            res.add(ap)

        baseLocal = None
        if not isExecutorExecute \
                and not ap.isStaticFieldRef() \
                and not callee.isStatic():
            if self.interproceduralCFG().isReflectiveCallSite(ie):
                baseLocal = ie.getArg(0)
            else:
                assert isinstance(ie, InstanceInvokeExpr)
                vie = ie
                baseLocal = vie.getBase()

        if baseLocal is not None:
            if aliasing.mayAlias(baseLocal, ap.getPlainValue()):
                if self.infoflow.manager.getTypeUtils().hasCompatibleTypesForCall(ap, callee.getDeclaringClass()):
                    if res is None:
                        res = HashSet()

                    if thisLocal is None:
                        thisLocal = callee.getActiveBody().getThisLocal()

                    res.add(self.infoflow.manager.getAccessPathFactory().copyWithNewValue(ap, thisLocal))

        if isExecutorExecute:
            if aliasing.mayAlias(ie.getArg(0), ap.getPlainValue()):
                if res is None:
                    res = HashSet()
                res.add(self.infoflow.manager.getAccessPathFactory().copyWithNewValue(ap, callee.getActiveBody().getThisLocal()))
        elif callee.getParameterCount() > 0:
            isReflectiveCallSite = self.interproceduralCFG().isReflectiveCallSite(ie)

            for i in range(1 if isReflectiveCallSite else 0, ie.getArgCount()):
                if aliasing.mayAlias(ie.getArg(i), ap.getPlainValue()):
                    if res is None:
                        res = HashSet()

                    if paramLocals is None:
                        paramLocals = callee.getActiveBody().getParameterLocals().toArray(Local[callee.getParameterCount()])

                    if isReflectiveCallSite:
                        for j in range(paramLocals.length):
                            newAP = self.infoflow.manager.getAccessPathFactory().copyWithNewValue(ap, paramLocals[j], None, False)
                            if newAP is not None:
                                res.add(newAP)
                    else:
                        newAP = self.infoflow.manager.getAccessPathFactory().copyWithNewValue(ap, paramLocals[i])
                        if newAP is not None:
                            res.add(newAP)
        return res
