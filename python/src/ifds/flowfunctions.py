from abc import *

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
import SolverNormalFlowFunction
import FlowFunctionType
from infoflowproblems import InfoflowProblem


class FlowFunctions(InfoflowProblem):

    def __init__(self, **kwargs):
        super(FlowFunctions, self).__init__(**kwargs)

    class NotifyingNormalFlowFunction(SolverNormalFlowFunction):

        def __init__(self, stmt=None, src=None, dest=None):
            super().__init__()
            self.stmt = stmt
            self.src = src
            self.dest = dest

        def computeTargets(self, d1, source):
            if self.taintPropagationHandler is not None:
                self.taintPropagationHandler.notifyFlowIn(self.stmt, source, self.manager, FlowFunctionType.NormalFlowFunction)

            res = self.computeTargetsInternal(d1, source)
            return self.notifyOutFlowHandlers( self.stmt, d1, source, res, FlowFunctionType.NormalFlowFunction )

        def computeTargetsInternal(self, d1, source):
            newSource = None
            if not source.isAbstractionActive() and self.src == source.getActivationUnit():
                newSource = source.getActiveCopy()
            else:
                newSource = source

            killSource = ByReferenceBoolean()
            killAll = ByReferenceBoolean()
            res = self.propagationRules.applyNormalFlowFunction( d1, newSource, self.stmt,
                                                                 self.dest, killSource, killAll )
            if killAll.value:
                return Collections.emptySet()

            if isinstance( self.src, AssignStmt ):
                assignStmt = self.src
                right = assignStmt.getRightOp()
                rightVals = BaseSelector.selectBaseList( right, True )

                resAssign = self.createNewTaintOnAssignment( assignStmt, rightVals, d1,
                                                             newSource )
                if resAssign is not None and not resAssign.isEmpty():
                    if res is not None:
                        res.addAll( resAssign )
                        return res
                    else:
                        res = resAssign

            return Collections.emptySet() if res == None or res.isEmpty() else res

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

    def addTaintViaStmt(self, d1, assignStmt, source, taintSet, cutFirstField, method, targetType):
        self.leftValue = assignStmt.getLeftOp()
        self.rightValue = assignStmt.getRightOp()

        if isinstance(self.leftValue, StaticFieldRef) \
            and self.manager.getConfig().getStaticFieldTrackingMode() == StaticFieldTrackingMode._None:
            return

        newAbs = None
        if not source.getAccessPath().isEmpty():
            if isinstance(self.leftValue, ArrayRef and targetType is not None):
                self.arrayRef = self.leftValue
                targetType = TypeUtils.buildArrayOrAddDimension(targetType, self.arrayRef.getType().getArrayType())

            if isinstance(self.rightValue, CastExpr):
                cast = assignStmt.getRightOp()
                targetType = cast.getType()
            elif isinstance(self.rightValue, InstanceOfExpr):
                newAbs = source.deriveNewAbstraction(self.manager.getAccessPathFactory().createAccessPath(
                    self.leftValue, BooleanType.v(), True, ArrayTaintType.ContentsAndLength), assignStmt)
        else:
            assert targetType == None

        self.arrayTaintType = source.getAccessPath().getArrayTaintType()
        if isinstance(self.leftValue, ArrayRef) and self.manager.getConfig().getEnableArraySizeTainting():
            self.arrayTaintType = ArrayTaintType.Contents

        if newAbs is None:
            if source.getAccessPath().isEmpty():
                newAbs = source.deriveNewAbstraction(
                        self.manager.getAccessPathFactory().createAccessPath(self.leftValue, True), assignStmt, True)
            else:
                ap = self.manager.getAccessPathFactory().copyWithNewValue(source.getAccessPath(),
                        self.leftValue, targetType, cutFirstField, True, self.arrayTaintType)
                newAbs = source.deriveNewAbstraction(ap, assignStmt)

        if newAbs is not None:
            if isinstance(self.leftValue, StaticFieldRef) \
                and self.manager.getConfig().getStaticFieldTrackingMode() == StaticFieldTrackingMode.ContextFlowInsensitive:
                self.manager.getGlobalTaintManager().addToGlobalTaintState(newAbs)
            else:
                taintSet.add(newAbs)
                aliasing = self.manager.getAliasing()
                if aliasing is not None and aliasing.canHaveAliases(assignStmt, self.leftValue, newAbs):
                    aliasing.computeAliases(d1, assignStmt, self.leftValue, taintSet, method, newAbs)

    def hasValidCallees(self, call):
        callees = self.interproceduralCFG().getCalleesOfCallAt(call)
        for callee in callees:
            if callee.isConcrete():
                return True
        return False

    def createNewTaintOnAssignment(self, assignStmt, rightVals, d1, newSource):
        leftValue = assignStmt.getLeftOp()
        rightValue = assignStmt.getRightOp()
        addLeftValue = False

        if isinstance(rightValue, LengthExpr):
            return Collections.singleton(newSource)


        implicitTaint = newSource.getTopPostdominator() is not None and newSource.getTopPostdominator().getUnit() is not None
        implicitTaint |= newSource.getAccessPath().isEmpty()

        if implicitTaint:
            if d1 is None or d1.getAccessPath().isEmpty() and not isinstance(leftValue, FieldRef):
                return Collections.singleton(newSource)

            if newSource.getAccessPath().isEmpty():
                addLeftValue = True

        aliasOverwritten = not addLeftValue \
                           and not newSource.isAbstractionActive() \
                           and Aliasing.baseMatchesStrict(rightValue, newSource) \
                           and isinstance(rightValue.getType(), RefType) \
                           and not newSource.dependsOnCutAP()

        aliasing = self.manager.getAliasing()
        if aliasing == None:
            return None

        cutFirstField = False
        mappedAP = newSource.getAccessPath()
        targetType = None
        if not addLeftValue and not aliasOverwritten:
            for rightVal in rightVals:
                if isinstance(rightVal, FieldRef):
                    rightRef = rightVal
                    if isinstance(rightRef, InstanceFieldRef) \
                            and isinstance(rightRef.getBase().getType(), NoneType):
                        return None

                    mappedAP = aliasing.mayAlias(newSource.getAccessPath(), rightRef)

                    if isinstance(rightVal, StaticFieldRef):
                        if self.manager.getConfig().getStaticFieldTrackingMode() is not StaticFieldTrackingMode._None \
                                and mappedAP is not None:
                            addLeftValue = True
                            cutFirstField = True
                    elif isinstance(rightVal, InstanceFieldRef):
                        rightBase = rightRef.getBase()
                        sourceBase = newSource.getAccessPath().getPlainValue()
                        rightField = rightRef.getField()

                        if mappedAP is not None:
                            addLeftValue = True
                            cutFirstField = (mappedAP.getFieldCount() > 0
                                    and mappedAP.getFirstField() == rightField)
                        elif (aliasing.mayAlias(rightBase, sourceBase)
                                and newSource.getAccessPath().getFieldCount() == 0
                                and newSource.getAccessPath().getTaintSubFields()):
                            addLeftValue = True
                            targetType = rightField.getType()
                            if (mappedAP == None):
                                mappedAP = self.manager.getAccessPathFactory().createAccessPath(rightBase, True)
                elif isinstance(rightVal, Local) and newSource.getAccessPath().isInstanceFieldRef():
                    base = newSource.getAccessPath().getPlainValue()
                    if aliasing.mayAlias(rightVal, base):
                        addLeftValue = True
                        targetType = newSource.getAccessPath().getBaseType()
                elif aliasing.mayAlias(rightVal, newSource.getAccessPath().getPlainValue()):
                    if not isinstance(assignStmt.getRightOp(), NewArrayExpr):
                        if self.manager.getConfig().getEnableArraySizeTainting() \
                                or not isinstance(rightValue, NewArrayExpr):
                            addLeftValue = True
                            targetType = newSource.getAccessPath().getBaseType()

                if addLeftValue:
                    break

        if not addLeftValue:
            return None

        if not newSource.isAbstractionActive() \
                and isinstance(assignStmt.getLeftOp().getType(), PrimType) \
                or TypeUtils.isStringType(assignStmt.getLeftOp().getType()) \
                and not newSource.getAccessPath().getCanHaveImmutableAliases():
            return Collections.singleton(newSource)

        res = HashSet()
        targetAB = newSource if mappedAP.equals(newSource.getAccessPath()) \
            else newSource.deriveNewAbstraction(mappedAP, None)
        self.addTaintViaStmt(d1, assignStmt, targetAB, res, cutFirstField,
                self.interproceduralCFG().getMethodOf(assignStmt), targetType)
        res.add(newSource)
        return res

    def getNormalFlowFunction(self, src, dest):
        if not isinstance(src, Stmt):
            return self.KillAll.v()

        return self.NotifyingNormalFlowFunction(self.stmt, src, dest)

    def getCallFlowFunction(self, src, dest):
        if not dest.isConcrete():
            #logger.debug("Call skipped because target has no body::} ->:}", src, dest)
            return KillAll.v()

        stmt = src
        ie = self.stmt.getInvokeExpr() if stmt is not None and self.stmt.containsInvokeExpr() else None

        paramLocals = dest.getActiveBody().getParameterLocals().toArray(Local[0])

        thisLocal = None if dest.isStatic() else dest.getActiveBody().getThisLocal()

        aliasing = self.manager.getAliasing()
        if aliasing == None:
            return KillAll.v()

        return self.SolverCallFlowFunction()

    class SolverCallFlowFunction():

        def computeTargets(self, d1, source):
            res = self.computeTargetsInternal( d1, source )
            if res is not None and not res.isEmpty() and d1 is not None:
                for abs in res:
                    self.aliasing.getAliasingStrategy().injectCallingContext( abs, self.solver, self.dest, self.src, source, d1 )
            return self.notifyOutFlowHandlers( self.stmt, d1, source, res, FlowFunctionType.CallFlowFunction )

        def computeTargetsInternal(self, d1, source):
            if self.manager.getConfig().getStopAfterFirstFlow() and not self.results.isEmpty():
                return None
            if source == self.getZeroValue():
                return None

            if self.isExcluded( self.dest ):
                return None

            if self.taintPropagationHandler is not None:
                self.taintPropagationHandler.notifyFlowIn( self.stmt, source, self.manager,
                                                           FlowFunctionType.CallFlowFunction )

            if not source.isAbstractionActive() and source.getActivationUnit() == self.src:
                source = source.getActiveCopy()

            killAll = ByReferenceBoolean()
            res = self.propagationRules.applyCallFlowFunction( d1, source, self.stmt, self.dest, killAll )
            if killAll.value:
                return None

            resMapping = self.mapAccessPathToCallee( self.dest, self.ie, self.paramLocals, self.thisLocal,
                                                     source.getAccessPath() )
            if resMapping == None:
                return res

            resAbs = HashSet( resMapping.size() )
            if res is not None and not res.isEmpty():
                resAbs.addAll( res )
            for ap in resMapping:
                if ap is not None:
                    if self.aliasing.getAliasingStrategy().isLazyAnalysis() \
                            or source.isImplicit() \
                            or self.interproceduralCFG().methodReadsValue( self.dest, ap.getPlainValue() ):
                        newAbs = source.deriveNewAbstraction( ap, self.stmt )
                        if newAbs is not None:
                            resAbs.add( newAbs )
            return resAbs

    def getReturnFlowFunction(self, callSite, callee, exitStmt, retSite):
        if callSite is not None and not isinstance(callSite, Stmt):
            return KillAll.v()
        iCallStmt = callSite
        isReflectiveCallSite = callSite is not None \
                               and self.interproceduralCFG().isReflectiveCallSite(callSite)

        returnStmt = exitStmt if isinstance(exitStmt, ReturnStmt) else None

        paramLocals = callee.getActiveBody().getParameterLocals().toArray(Local[0])

        aliasing = self.manager.getAliasing()
        if (aliasing == None):
            return KillAll.v()

        thisLocal = None if callee.isStatic() else callee.getActiveBody().getThisLocal()

        return self.SolverReturnFlowFunction()

    class SolverReturnFlowFunction():

        def computeTargets(self, source, d1, callerD1s):
            res = self.computeTargetsInternal(source, callerD1s)
            return self.notifyOutFlowHandlers(exitStmt, d1, source, res, FlowFunctionType.ReturnFlowFunction)

        def computeTargetsInternal(self, source, callerD1s):
            if self.manager.getConfig().getStopAfterFirstFlow() and not results.isEmpty():
                return None
            if source == getZeroValue()
                return None

            if (taintPropagationHandler is not None)
                taintPropagationHandler.notifyFlowIn(exitStmt, source, manager, FlowFunctionType.ReturnFlowFunction)
            callerD1sConditional = False
            for d1 in callerD1s:
                if d1.getAccessPath().isEmpty():
                    callerD1sConditional = True
                    break
            newSource = source
            if not source.isAbstractionActive():
                if callSite is not None:
                    if callSite == source.getActivationUnit() \
                            or self.isCallSiteActivatingTaint(callSite, source.getActivationUnit()):
                        newSource = source.getActiveCopy()

            if not newSource.isAbstractionActive() and newSource.getActivationUnit() is not None:
                if self.interproceduralCFG().getMethodOf(newSource.getActivationUnit()) == callee:
                    return None

            killAll = ByReferenceBoolean()
            res = self.propagationRules.applyReturnFlowFunction(callerD1s, newSource, exitStmt, retSite,
                                                                callSite, killAll)
            if killAll.value:
                return None
            if res is None:
                res = HashSet()

            if callSite == None:
                return None

            if aliasing.getAliasingStrategy().isLazyAnalysis() \
                    and Aliasing.canHaveAliases(newSource.getAccessPath()):
                res.add(newSource)

            if not newSource.getAccessPath().isStaticFieldRef() and not callee.isStaticInitializer():
                if returnStmt is not None and isinstance(callSite, DefinitionStmt):
                    retLocal = returnStmt.getOp()
                    defnStmt = callSite
                    leftOp = defnStmt.getLeftOp()

                    if aliasing.mayAlias(retLocal, newSource.getAccessPath().getPlainValue()) \
                            and not self.isExceptionHandler(retSite):
                        ap = self.manager.getAccessPathFactory().copyWithNewValue(newSource.getAccessPath(), leftOp)
                        abs = newSource.deriveNewAbstraction(ap, exitStmt)
                        if abs is not None:
                            res.add(abs)
                            if aliasing.getAliasingStrategy().requiresAnalysisOnReturn():
                                for d1 in callerD1s:
                                    aliasing.computeAliases(d1, iCallStmt, leftOp, res,
                                            self.interproceduralCFG().getMethodOf(callSite), abs)

                sourceBase = newSource.getAccessPath().getPlainValue()
                parameterAliases = False
                originalCallArg = None
                for i in range(callee.getParameterCount()):
                    if isinstance(callSite, DefinitionStmt) and not isExceptionHandler(retSite):
                        defnStmt = callSite
                        leftOp = defnStmt.getLeftOp()
                        originalCallArg = defnStmt.getInvokeExpr().getArg(i)
                        if originalCallArg == leftOp:
                            continue

                    if aliasing.mayAlias(paramLocals[i], sourceBase):
                        parameterAliases = True
                        originalCallArg = iCallStmt.getInvokeExpr().getArg(1 if isReflectiveCallSite else i)

                        if not AccessPath.canContainValue(originalCallArg):
                            continue
                        if not isReflectiveCallSite \
                                and not manager.getTypeUtils().checkCast(source.getAccessPath(),
                                                                         originalCallArg.getType()):
                            continue

                        if isinstance(source.getAccessPath().getBaseType(), PrimType):
                            continue
                        if TypeUtils.isStringType(source.getAccessPath().getBaseType()) \
                                and not source.getAccessPath().getCanHaveImmutableAliases():
                            continue

                        if not source.getAccessPath().getTaintSubFields():
                            continue

                        if self.interproceduralCFG().methodWritesValue(callee, paramLocals[i]):
                            continue

                        ap = manager.getAccessPathFactory().copyWithNewValue(
                                newSource.getAccessPath(), originalCallArg,
                                None if isReflectiveCallSite else newSource.getAccessPath().getBaseType(),
                                False)
                        abs = newSource.deriveNewAbstraction(ap, exitStmt)

                        if abs is not None:
                            res.add(abs)

                thisAliases = False
                if isinstance(callSite, DefinitionStmt) and not isExceptionHandler(retSite):
                    defnStmt = callSite
                    leftOp = defnStmt.getLeftOp()
                    if thisLocal == leftOp:
                        thisAliases = True

                if not parameterAliases and not thisAliases and source.getAccessPath().getTaintSubFields() \
                        and isinstance(self.iCallStmt.getInvokeExpr(), InstanceInvokeExpr) \
                        and aliasing.mayAlias(thisLocal, sourceBase):

                    if self.manager.getTypeUtils().checkCast(source.getAccessPath(), thisLocal.getType()):
                        iIExpr = self.iCallStmt.getInvokeExpr()

                        callerBaseLocal = iIExpr.getArg(0)\
                            if self.interproceduralCFG().isReflectiveCallSite(iIExpr) else iIExpr.getBase()
                        ap = self.manager.getAccessPathFactory().copyWithNewValue(
                                newSource.getAccessPath(), callerBaseLocal,
                                None if isReflectiveCallSite else newSource.getAccessPath().getBaseType(),
                                False)
                        abs = newSource.deriveNewAbstraction(ap, self.exitStmt)
                        if abs is not None:
                            res.add(abs)

            for abs in res:
                if abs.isImplicit() and not callerD1sConditional \
                        or aliasing.getAliasingStrategy().requiresAnalysisOnReturn():
                    for d1 in callerD1s:
                        aliasing.computeAliases(d1, self.iCallStmt, None, res,
                                self.interproceduralCFG().getMethodOf(callSite), abs)

                if abs != newSource:
                    abs.setCorrespondingCallSite(iCallStmt)
            return res

    def getCallToReturnFlowFunction(self, call, returnSite):
        if not isinstance(call, Stmt):
            return KillAll.v()

        iCallStmt = call
        invExpr = iCallStmt.getInvokeExpr()

        aliasing = self.manager.getAliasing()
        if aliasing == None:
            return KillAll.v()

        callArgs = Value[invExpr.getArgCount()]
        for i in range(invExpr.getArgCount()):
            callArgs[i] = invExpr.getArg(i)

        isSink = self.manager.getSourceSinkManager().getSinkInfo(iCallStmt, self.manager, None) is not None \
            if (self.manager.getSourceSinkManager() is not None) \
            else False
        isSource = self.manager.getSourceSinkManager().getSourceInfo(iCallStmt, manager) is not None \
            if self.manager.getSourceSinkManager() is not None \
            else False

        callee = invExpr.getMethod()
        hasValidCallees = hasValidCallees(call)

        return new SolverCallToReturnFlowFunction():

        class SolverCallToReturnFlowFunction():

            def computeTargets(self, d1, source):
                res = self.computeTargetsInternal(d1, source)
                return self.notifyOutFlowHandlers(call, d1, source, res, FlowFunctionType.CallToReturnFlowFunction)

            def computeTargetsInternal(self, d1, source):
                if self.manager.getConfig().getStopAfterFirstFlow() and not results.isEmpty():
                    return None

                if self.taintPropagationHandler is not None:
                    self.taintPropagationHandler.notifyFlowIn(call, source, manager,
                            FlowFunctionType.CallToReturnFlowFunction)

                newSource = None
                if not source.isAbstractionActive() \
                        and call == source.getActivationUnit() \
                        or self.isCallSiteActivatingTaint(call, source.getActivationUnit()):
                    newSource = source.getActiveCopy()
                else:
                    newSource = source

                killSource = ByReferenceBoolean()
                killAll = ByReferenceBoolean()
                res = self.propagationRules.applyCallToReturnFlowFunction(d1, newSource, iCallStmt,
                        killSource, killAll, True)
                if killAll.value:
                    return None
                passOn = not killSource.value

                if source == getZeroValue():
                    return Collections.emptySet() if res == None or res.isEmpty() else res

                if res == None:
                    res = HashSet()

                if newSource.getTopPostdominator() is not None \
                        and newSource.getTopPostdominator().getUnit() is None:
                    return Collections.singleton(newSource)

                if newSource.getAccessPath().isStaticFieldRef():
                    passOn = False

                if passOn \
                        and isinstance(invExpr, InstanceInvokeExpr) \
                        and (manager.getConfig().getInspectSources() or not isSource) \
                        and (manager.getConfig().getInspectSinks() or not isSink) \
                        and newSource.getAccessPath().isInstanceFieldRef() \
                        and (hasValidCallees \
                            or (taintWrapper is not None and taintWrapper.isExclusive(iCallStmt, newSource))):

                    callees = self.interproceduralCFG().getCalleesOfCallAt(call)
                    allCalleesRead = not callees.isEmpty()
                    for callee in callees:
                        if callee.isConcrete() and callee.hasActiveBody():
                            calleeAPs = mapAccessPathToCallee(callee, invExpr, None, None, source.getAccessPath())
                            if calleeAPs is not None:
                                for ap in calleeAPs:
                                    if ap is not None:
                                        if not self.interproceduralCFG().methodReadsValue(callee, ap.getPlainValue()):
                                            allCalleesRead = False
                                            break

                        if self.isExcluded(callee):
                            allCalleesRead = False
                            break

                    if allCalleesRead:
                        if aliasing.mayAlias(invExpr.getBase(), newSource.getAccessPath().getPlainValue()):
                            passOn = False
                        if passOn:
                            for i in range(callArgs.length):
                                if aliasing.mayAlias(callArgs[i], newSource.getAccessPath().getPlainValue()):
                                    passOn = False
                                    break
                        if newSource.getAccessPath().isStaticFieldRef():
                            passOn = False

                if source.getAccessPath().isStaticFieldRef():
                    if not self.interproceduralCFG().isStaticFieldUsed(callee, source.getAccessPath().getFirstField()):
                        passOn = True

                passOn |= source.getTopPostdominator() is not None or source.getAccessPath().isEmpty()
                if passOn:
                    if newSource != getZeroValue():
                        res.add(newSource)

                if callee.isNative():
                    for callVal in callArgs:
                        if callVal == newSource.getAccessPath().getPlainValue():
                            nativeAbs = ncHandler.getTaintedValues(iCallStmt, newSource, callArgs)
                            if nativeAbs is not None:
                                res.addAll(nativeAbs)

                                for abs in nativeAbs:
                                    if abs.getAccessPath().isStaticFieldRef() \
                                            or aliasing.canHaveAliases(iCallStmt,
                                                                       abs.getAccessPath().getCompleteValue(),
                                                                       abs):
                                        aliasing.computeAliases(d1, iCallStmt,
                                                abs.getAccessPath().getPlainValue(), res,
                                                self.interproceduralCFG().getMethodOf(call), abs)
                            break

                for abs in res:
                    if abs != newSource:
                        abs.setCorrespondingCallSite(iCallStmt)

                return res


    def mapAccessPathToCallee(self, callee, ie, paramLocals, thisLocal, ap):
        if ap.isEmpty():
            return None

        isExecutorExecute = self.interproceduralCFG().isExecutorExecute(ie, callee)

        res = None

        aliasing = self.manager.getAliasing()
        if aliasing == None:
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
                if self.manager.getTypeUtils().hasCompatibleTypesForCall(ap, callee.getDeclaringClass()):
                    if res == None:
                        res = HashSet()

                    if thisLocal == None:
                        thisLocal = callee.getActiveBody().getThisLocal()

                    res.add(self.manager.getAccessPathFactory().copyWithNewValue(ap, thisLocal))

        if isExecutorExecute:
            if aliasing.mayAlias(ie.getArg(0), ap.getPlainValue()):
                if res == None:
                    res = HashSet()
                res.add(sefl.manager.getAccessPathFactory().copyWithNewValue(ap, callee.getActiveBody().getThisLocal()))
        elif callee.getParameterCount() > 0:
            isReflectiveCallSite = self.interproceduralCFG().isReflectiveCallSite(ie)

            for i in range(1 if isReflectiveCallSite else 0, ie.getArgCount()):
                if aliasing.mayAlias(ie.getArg(i), ap.getPlainValue()):
                    if res == None:
                        res = HashSet()

                    if paramLocals == None:
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
