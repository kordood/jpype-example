from abstractinfoflowproblem import AbstractInfoflowProblem
from solvernormalflowfunction import SolverNormalFlowFunction
from flowfunctions import FlowFunctions
import TaintPropagationResults
import FlowFunctionType
import StaticFieldRef, ArrayRef, FieldRef, RefType, NoneType, InstanceFieldRef
import CastExpr, InstanceOfExpr
import StaticFieldTrackingMode
import TypeUtils, BooleanType, ArrayTaintType
import LengthExpr, AssignStmt, Stmt
import Collections
import Aliasing
import NewArrayExpr
import Local
import PrimType
import HashSet
import ByReferenceBoolean, BaseSelector
import KillAll

from abc import *

class InfoflowProblem(AbstractInfoflowProblem):
    def __init__(self, manager, zeroValue, ruleManagerFactory):
        super(InfoflowProblem, self).__init__(manager)

        self.zeroValue = self.createZeroValue() if zeroValue == None else zeroValue
        self.results = self.TaintPropagationResults( manager )
        self.propagationRules = ruleManagerFactory.createRuleManager( manager, self.zeroValue, self.results )

    def createFlowFunctionsFactory(self):
        return self.FlowFunctions()


    class NotifyingNormalFlowFunction(AbstractInfoflowProblem.NotifyingNormalFlowFunction, SolverNormalFlowFunction):

        def __init__(self, stmt):
            super().__init__()
            self.stmt = stmt

        def _computeTargets(self, d1, source):
            if self.taintPropagationHandler is not None:
                self.taintPropagationHandler.notifyFlowIn(self.stmt, source, self.manager, FlowFunctionType.NormalFlowFunction)

            res = self.computeTargetsInternal(d1, source)
            return self.notifyOutFlowHandlers( self.stmt, d1, source, res, FlowFunctionType.NormalFlowFunction )

        def computeTargetsInternal(self, d1, source):
            pass


class FlowFunctionsFactory(FlowFunctions):

    def __init__(self):
        super(FlowFunctionsFactory, self).__init__()
        pass

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

        return NotifyingNormalFlowFunction(self.stmt, src, dest)

    class NotifyingNormalFlowFunction():  # have to fix, especially src

        def __init__(self, stmt, src, dest):
            super().__init__( stmt )
            self.src = src
            self.dest = dest

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

        return self.SolverCallFlowFunction() # Todo: this inner class needs fix!!

    class SolverCallFlowFunction(FlowFunctionsFactory):  # Have to fix!!

        def __init__(self):
            super(SolverCallFlowFunction, self).__init__()
            pass

        def computeTargets(self, d1, source):
            res = self.computeTargetsInternal( d1, source )
            if res is not None and not res.isEmpty() and d1 is not None:
                for abs in res:
                    aliasing.getAliasingStrategy().injectCallingContext( abs, self.solver, self.dest, self.src, source, d1 )
            return self.notifyOutFlowHandlers( self.stmt, d1, source, res, FlowFunctionType.CallFlowFunction )

        def computeTargetsInternal(self, d1, source):
            if self.manager.getConfig().getStopAfterFirstFlow() and not results.isEmpty():
                return None
            if source == getZeroValue():
                return None

            if isExcluded( self.dest ):
                return None

            if self.taintPropagationHandler is not None:
                self.taintPropagationHandler.notifyFlowIn( self.stmt, source, manager,
                                                           FlowFunctionType.CallFlowFunction )

            if not source.isAbstractionActive() and source.getActivationUnit() == src:
                source = source.getActiveCopy()

            killAll = ByReferenceBoolean()
            res = self.propagationRules.applyCallFlowFunction( d1, source, self.stmt, self.dest, killAll )
            if killAll.value:
                return None

            resMapping = self.mapAccessPathToCallee( self.dest, self.ie, paramLocals, thisLocal,
                                                     source.getAccessPath() )
            if resMapping == None:
                return res

            resAbs = HashSet( resMapping.size() )
            if res is not None and not res.isEmpty():
                resAbs.addAll( res )
            for ap in resMapping:
                if ap is not None:
                    if aliasing.getAliasingStrategy().isLazyAnalysis() \
                            or source.isImplicit() \
                            or self.interproceduralCFG().methodReadsValue( self.dest, ap.getPlainValue() ):
                        newAbs = source.deriveNewAbstraction( ap, self.stmt )
                        if newAbs is not None:
                            resAbs.add( newAbs )
            return resAbs

    FlowFunction<Abstraction> getReturnFlowFunction( Unit callSite,  SootMethod callee,
             Unit exitStmt,  Unit retSite):
        // Get the call site
        if (callSite is not None and !(callSite,_ins Stmt))
            return KillAll.v()
         Stmt iCallStmt = callSite
         boolean isReflectiveCallSite = callSite is not None
                and interproceduralCFG().isReflectiveCallSite(callSite)

         ReturnStmt returnStmt = (exitStmt,_ins ReturnStmt) ? (ReturnStmt) exitStmt : None

         Local[] paramLocals = callee.getActiveBody().getParameterLocals().toArray(new Local[0])

        // If we can't reason about aliases, there's little we can do here
         Aliasing aliasing = manager.getAliasing()
        if (aliasing == None)
            return KillAll.v()

        // This is not cached by Soot, so accesses are more expensive
        // than one might think
         Local thisLocal = callee.isStatic() ? None : callee.getActiveBody().getThisLocal()

        return new SolverReturnFlowFunction():

            @Override
            Set<Abstraction> computeTargets(Abstraction source, Abstraction d1,
                    Collection<Abstraction> callerD1s):
                Set<Abstraction> res = computeTargetsInternal(source, callerD1s)
                return notifyOutFlowHandlers(exitStmt, d1, source, res, FlowFunctionType.ReturnFlowFunction)
            }

            Set<Abstraction> computeTargetsInternal(Abstraction source,
                    Collection<Abstraction> callerD1s):
                if (manager.getConfig().getStopAfterFirstFlow() and !results.isEmpty())
                    return None
                if (source == getZeroValue())
                    return None

                // Notify the handler if we have one
                if (taintPropagationHandler is not None)
                    taintPropagationHandler.notifyFlowIn(exitStmt, source, manager,
                            FlowFunctionType.ReturnFlowFunction)
                def callerD1sConditional = False
                for (Abstraction d1 : callerD1s):
                    if (d1.getAccessPath().isEmpty()):
                        callerD1sConditional = True
                        break
                    }
                }

                // Activate taint if necessary
                Abstraction newSource = source
                if (!source.isAbstractionActive())
                    if (callSite is not None)
                        if (callSite == source.getActivationUnit()
                                or isCallSiteActivatingTaint(callSite, source.getActivationUnit()))
                            newSource = source.getActiveCopy()

                // if abstraction is not active and activeStmt was in
                // this method, it will not get activated = it can be
                // removed:
                if (!newSource.isAbstractionActive() and newSource.getActivationUnit() is not None)
                    if (interproceduralCFG().getMethodOf(newSource.getActivationUnit()) == callee)
                        return None

                ByReferenceBoolean killAll = new ByReferenceBoolean()
                Set<Abstraction> res = propagationRules.applyReturnFlowFunction(callerD1s, newSource,
                        exitStmt, retSite, callSite, killAll)
                if (killAll.value)
                    return None
                if (res == None)
                    res = new HashSet<>()

                // If we have no caller, we have nowhere to propagate.
                // This can happen when leaving the main method.
                if (callSite == None)
                    return None

                // Do we need to retain all the taints?
                if (aliasing.getAliasingStrategy().isLazyAnalysis()
                        and Aliasing.canHaveAliases(newSource.getAccessPath()))
                    res.add(newSource)

                // Static fields are handled in a rule
                if (!newSource.getAccessPath().isStaticFieldRef() and !callee.isStaticInitializer()):
                    // if we have a returnStmt we have to look at the
                    // returned value:
                    if (returnStmt is not None and callSite,_ins DefinitionStmt):
                        Value retLocal = returnStmt.getOp()
                        DefinitionStmt defnStmt = (DefinitionStmt) callSite
                        Value leftOp = defnStmt.getLeftOp()

                        if (aliasing.mayAlias(retLocal, newSource.getAccessPath().getPlainValue())
                                and !isExceptionHandler(retSite)):
                            AccessPath ap = manager.getAccessPathFactory()
                                    .copyWithNewValue(newSource.getAccessPath(), leftOp)
                            Abstraction abs = newSource.deriveNewAbstraction(ap, exitStmt)
                            if (abs is not None):
                                res.add(abs)

                                // Aliases of implicitly tainted variables must be mapped back into the caller's
                                // context on return when we leave the last implicitly-called method
                                if (aliasing.getAliasingStrategy().requiresAnalysisOnReturn())
                                    for (Abstraction d1 : callerD1s)
                                        aliasing.computeAliases(d1, iCallStmt, leftOp, res,
                                                interproceduralCFG().getMethodOf(callSite), abs)
                            }
                        }
                    }

                    // Check parameters
                    Value sourceBase = newSource.getAccessPath().getPlainValue()
                    def parameterAliases = False
                    {
                        Value originalCallArg = None
                        for (int i = 0 i < callee.getParameterCount() i++):
                            // If this parameter is overwritten, we
                            // cannot propagate the "old" taint over.
                            // Return value propagation must always
                            // happen explicitly.
                            if (callSite,_ins DefinitionStmt and !isExceptionHandler(retSite)):
                                DefinitionStmt defnStmt = (DefinitionStmt) callSite
                                Value leftOp = defnStmt.getLeftOp()
                                originalCallArg = defnStmt.getInvokeExpr().getArg(i)
                                if (originalCallArg == leftOp)
                                    continue
                            }

                            // Propagate over the parameter taint
                            if (aliasing.mayAlias(paramLocals[i], sourceBase)):
                                parameterAliases = True
                                originalCallArg = iCallStmt.getInvokeExpr()
                                        .getArg(isReflectiveCallSite ? 1 : i)

                                // If this is a constant parameter, we
                                // can
                                // safely ignore it
                                if (!AccessPath.canContainValue(originalCallArg))
                                    continue
                                if (!isReflectiveCallSite and !manager.getTypeUtils()
                                        .checkCast(source.getAccessPath(), originalCallArg.getType()))
                                    continue

                                // Primitive types and strings cannot
                                // have aliases and thus never need to
                                // be propagated back
                                if (source.getAccessPath().getBaseType(),_ins PrimType)
                                    continue
                                if (TypeUtils.isStringType(source.getAccessPath().getBaseType())
                                        and !source.getAccessPath().getCanHaveImmutableAliases())
                                    continue

                                // If only the object itself, but no
                                // field is tainted, we can safely
                                // ignore it
                                if (!source.getAccessPath().getTaintSubFields())
                                    continue

                                // If the variable was overwritten
                                // somewehere in the callee, we assume
                                // it to overwritten on all paths (yeah,
                                // I know ...) Otherwise, we need SSA
                                // or lots of bookkeeping to avoid FPs
                                // (BytecodeTests.flowSensitivityTest1).
                                if (interproceduralCFG().methodWritesValue(callee, paramLocals[i]))
                                    continue

                                AccessPath ap = manager.getAccessPathFactory().copyWithNewValue(
                                        newSource.getAccessPath(), originalCallArg,
                                        isReflectiveCallSite ? None : newSource.getAccessPath().getBaseType(),
                                        False)
                                Abstraction abs = newSource.deriveNewAbstraction(ap, exitStmt)

                                if (abs is not None):
                                    res.add(abs)
                                }
                            }
                        }
                    }

                    // If this parameter is overwritten, we
                    // cannot propagate the "old" taint over. Return
                    // value propagation must always happen explicitly.
                    def thisAliases = False
                    if (callSite,_ins DefinitionStmt and !isExceptionHandler(retSite)):
                        DefinitionStmt defnStmt = (DefinitionStmt) callSite
                        Value leftOp = defnStmt.getLeftOp()
                        if (thisLocal == leftOp)
                            thisAliases = True
                    }

                    // check if it is not one of the params
                    // (then we have already fixed it)
                    if (!parameterAliases and !thisAliases and source.getAccessPath().getTaintSubFields()
                            and iCallStmt.getInvokeExpr(),_ins InstanceInvokeExpr
                            and aliasing.mayAlias(thisLocal, sourceBase)):
                        // Type check
                        if (manager.getTypeUtils().checkCast(source.getAccessPath(), thisLocal.getType())):
                            InstanceInvokeExpr iIExpr = (InstanceInvokeExpr) iCallStmt.getInvokeExpr()

                            // Get the caller-side base local
                            // and create a new access path for it
                            Value callerBaseLocal = interproceduralCFG().isReflectiveCallSite(iIExpr)
                                    ? iIExpr.getArg(0)
                                    : iIExpr.getBase()
                            AccessPath ap = manager.getAccessPathFactory().copyWithNewValue(
                                    newSource.getAccessPath(), callerBaseLocal,
                                    isReflectiveCallSite ? None : newSource.getAccessPath().getBaseType(),
                                    False)
                            Abstraction abs = newSource.deriveNewAbstraction(ap, exitStmt)
                            if (abs is not None):
                                res.add(abs)
                            }
                        }
                    }
                }

                for (Abstraction abs : res):
                    // Aliases of implicitly tainted variables must be
                    // mapped back into the caller's context on return
                    // when we leave the last implicitly-called method
                    if ((abs.isImplicit() and !callerD1sConditional)
                            or aliasing.getAliasingStrategy().requiresAnalysisOnReturn()):
                        for (Abstraction d1 : callerD1s):
                            aliasing.computeAliases(d1, iCallStmt, None, res,
                                    interproceduralCFG().getMethodOf(callSite), abs)
                        }
                    }

                    // Set the corresponding call site
                    if (abs != newSource):
                        abs.setCorrespondingCallSite(iCallStmt)
                    }
                }
                return res
            }

        }
    }

    @Override
    FlowFunction<Abstraction> getCallToReturnFlowFunction( Unit call,  Unit returnSite):
        // special treatment for native methods:
        if (!(call,_ins Stmt))
            return KillAll.v()

         Stmt iCallStmt = call
         InvokeExpr invExpr = iCallStmt.getInvokeExpr()

        // If we can't reason about aliases, there's little we can do here
         Aliasing aliasing = manager.getAliasing()
        if (aliasing == None)
            return KillAll.v()

         Value[] callArgs = new Value[invExpr.getArgCount()]
        for (int i = 0 i < invExpr.getArgCount() i++)
            callArgs[i] = invExpr.getArg(i)

         boolean isSink = (manager.getSourceSinkManager() is not None)
                ? manager.getSourceSinkManager().getSinkInfo(iCallStmt, manager, None) is not None
                : False
         boolean isSource = (manager.getSourceSinkManager() is not None)
                ? manager.getSourceSinkManager().getSourceInfo(iCallStmt, manager) is not None
                : False

         SootMethod callee = invExpr.getMethod()
         boolean hasValidCallees = hasValidCallees(call)

        return new SolverCallToReturnFlowFunction():

            @Override
            Set<Abstraction> computeTargets(Abstraction d1, Abstraction source):
                Set<Abstraction> res = computeTargetsInternal(d1, source)
                return notifyOutFlowHandlers(call, d1, source, res, FlowFunctionType.CallToReturnFlowFunction)
            }

            Set<Abstraction> computeTargetsInternal(Abstraction d1, Abstraction source):
                if (manager.getConfig().getStopAfterFirstFlow() and !results.isEmpty())
                    return None

                // Notify the handler if we have one
                if (taintPropagationHandler is not None)
                    taintPropagationHandler.notifyFlowIn(call, source, manager,
                            FlowFunctionType.CallToReturnFlowFunction)

                // check inactive elements:
                 Abstraction newSource
                if (!source.isAbstractionActive() and (call == source.getActivationUnit()
                        or isCallSiteActivatingTaint(call, source.getActivationUnit())))
                    newSource = source.getActiveCopy()
                else
                    newSource = source

                ByReferenceBoolean killSource = new ByReferenceBoolean()
                ByReferenceBoolean killAll = new ByReferenceBoolean()
                Set<Abstraction> res = propagationRules.applyCallToReturnFlowFunction(d1, newSource, iCallStmt,
                        killSource, killAll, True)
                if (killAll.value)
                    return None
                def passOn = !killSource.value

                // Do not propagate zero abstractions
                if (source == getZeroValue())
                    return res == None or res.isEmpty() ? Collections.<Abstraction>emptySet() : res

                // Initialize the result set
                if (res == None)
                    res = new HashSet<>()

                if (newSource.getTopPostdominator() is not None
                        and newSource.getTopPostdominator().getUnit() == None)
                    return Collections.singleton(newSource)

                // Static taints must always go through the callee
                if (newSource.getAccessPath().isStaticFieldRef())
                    passOn = False

                // we only can remove the taint if we step into the
                // call/return edges
                // otherwise we will loose taint - see
                // ArrayTests/arrayCopyTest
                if (passOn and invExpr,_ins InstanceInvokeExpr
                        and (manager.getConfig().getInspectSources() or !isSource)
                        and (manager.getConfig().getInspectSinks() or !isSink)
                        and newSource.getAccessPath().isInstanceFieldRef() and (hasValidCallees
                                or (taintWrapper is not None and taintWrapper.isExclusive(iCallStmt, newSource)))):
                    // If one of the callers does not read the value, we
                    // must pass it on in any case
                    Collection<SootMethod> callees = interproceduralCFG().getCalleesOfCallAt(call)
                    def allCalleesRead = !callees.isEmpty()
                    outer: for (SootMethod callee : callees):
                        if (callee.isConcrete() and callee.hasActiveBody()):
                            Set<AccessPath> calleeAPs = mapAccessPathToCallee(callee, invExpr, None, None,
                                    source.getAccessPath())
                            if (calleeAPs is not None):
                                for (AccessPath ap : calleeAPs):
                                    if (ap is not None):
                                        if (!interproceduralCFG().methodReadsValue(callee,
                                                ap.getPlainValue())):
                                            allCalleesRead = False
                                            break outer
                                        }
                                    }
                                }
                            }
                        }

                        // Additional check: If all callees are library
                        // classes, we pass it on as well
                        if (isExcluded(callee)):
                            allCalleesRead = False
                            break
                        }
                    }

                    if (allCalleesRead):
                        if (aliasing.mayAlias(((InstanceInvokeExpr) invExpr).getBase(),
                                newSource.getAccessPath().getPlainValue())):
                            passOn = False
                        }
                        if (passOn)
                            for (int i = 0 i < callArgs.length i++)
                                if (aliasing.mayAlias(callArgs[i], newSource.getAccessPath().getPlainValue())):
                                    passOn = False
                                    break
                                }
                        // static variables are always propagated if
                        // they are not overwritten. So if we have at
                        // least one call/return edge pair,
                        // we can be sure that the value does not get
                        // "lost" if we do not pass it on:
                        if (newSource.getAccessPath().isStaticFieldRef())
                            passOn = False
                    }
                }

                // If the callee does not read the given value, we also
                // need to pass it on since we do not propagate it into
                // the callee.
                if (source.getAccessPath().isStaticFieldRef()):
                    if (!interproceduralCFG().isStaticFieldUsed(callee, source.getAccessPath().getFirstField()))
                        passOn = True
                }

                // Implicit taints are always passed over conditionally
                // called methods
                passOn |= source.getTopPostdominator() is not None or source.getAccessPath().isEmpty()
                if (passOn):
                    if (newSource != getZeroValue())
                        res.add(newSource)
                }

                if (callee.isNative())
                    for (Value callVal : callArgs)
                        if (callVal == newSource.getAccessPath().getPlainValue()):
                            // java uses call by value, but fields of
                            // complex objects can be changed (and
                            // tainted), so use this conservative
                            // approach:
                            Set<Abstraction> nativeAbs = ncHandler.getTaintedValues(iCallStmt, newSource,
                                    callArgs)
                            if (nativeAbs is not None):
                                res.addAll(nativeAbs)

                                // Compute the aliases
                                for (Abstraction abs : nativeAbs)
                                    if (abs.getAccessPath().isStaticFieldRef() or aliasing.canHaveAliases(
                                            iCallStmt, abs.getAccessPath().getCompleteValue(), abs))
                                        aliasing.computeAliases(d1, iCallStmt,
                                                abs.getAccessPath().getPlainValue(), res,
                                                interproceduralCFG().getMethodOf(call), abs)
                            }

                            // We only call the native code handler once
                            // per statement
                            break
                        }

                for (Abstraction abs : res)
                    if (abs != newSource)
                        abs.setCorrespondingCallSite(iCallStmt)

                return res
            }
        }
    }

    /**
     * Maps the given access path into the scope of the callee
     *
     * @param callee      The method that is being called
     * @param ie          The invocation expression for the call
     * @param paramLocals The list of parameter locals in the callee
     * @param thisLocal   The "this" local in the callee
     * @param ap          The caller-side access path to map
     * @return The set of callee-side access paths corresponding to the given
     *         caller-side access path
     */
    Set<AccessPath> mapAccessPathToCallee( SootMethod callee,  InvokeExpr ie,
            Value[] paramLocals, Local thisLocal, AccessPath ap):
        // We do not transfer empty access paths
        if (ap.isEmpty())
            return None

        // Android executor methods are handled specially.
        // getSubSignature() is slow, so we try to avoid it whenever we can
         boolean isExecutorExecute = interproceduralCFG().isExecutorExecute(ie, callee)

        Set<AccessPath> res = None

        // If we can't reason about aliases, there's little we can do here
         Aliasing aliasing = manager.getAliasing()
        if (aliasing == None)
            return None

        // If we are performing lazy aliasing, we need to retain all
        // taints
        if (aliasing.getAliasingStrategy().isLazyAnalysis() and Aliasing.canHaveAliases(ap)):
            res = new HashSet<>()
            res.add(ap)
        }

        // Is this a virtual method call?
        Value baseLocal = None
        if (!isExecutorExecute and !ap.isStaticFieldRef() and !callee.isStatic()):
            if (interproceduralCFG().isReflectiveCallSite(ie)):
                // Method.invoke(target, arg0, ..., argn)
                baseLocal = ie.getArg(0)
            } else:
                assert ie,_ins InstanceInvokeExpr
                InstanceInvokeExpr vie = (InstanceInvokeExpr) ie
                baseLocal = vie.getBase()
            }
        }

        // If we have a base local to map, we need to find the
        // corresponding "this" local
        if (baseLocal is not None):
            if (aliasing.mayAlias(baseLocal, ap.getPlainValue()))
                if (manager.getTypeUtils().hasCompatibleTypesForCall(ap, callee.getDeclaringClass())):
                    if (res == None)
                        res = new HashSet<AccessPath>()

                    // Get the "this" local if we don't have it yet
                    if (thisLocal == None)
                        thisLocal = callee.getActiveBody().getThisLocal()

                    res.add(manager.getAccessPathFactory().copyWithNewValue(ap, thisLocal))
                }
        }

        // special treatment for clinit methods - no param mapping
        // possible
        if (isExecutorExecute):
            if (aliasing.mayAlias(ie.getArg(0), ap.getPlainValue())):
                if (res == None)
                    res = new HashSet<AccessPath>()
                res.add(manager.getAccessPathFactory().copyWithNewValue(ap,
                        callee.getActiveBody().getThisLocal()))
            }
        elif (callee.getParameterCount() > 0):
            def isReflectiveCallSite = interproceduralCFG().isReflectiveCallSite(ie)

            // check if param is tainted:
            for (int i = isReflectiveCallSite ? 1 : 0 i < ie.getArgCount() i++):
                if (aliasing.mayAlias(ie.getArg(i), ap.getPlainValue())):
                    if (res == None)
                        res = new HashSet<AccessPath>()

                    // Get the parameter locals if we don't have them
                    // yet
                    if (paramLocals == None)
                        paramLocals = callee.getActiveBody().getParameterLocals()
                                .toArray(new Local[callee.getParameterCount()])

                    if (isReflectiveCallSite):
                        // Taint all parameters in the callee if the
                        // argument array of a
                        // reflective method call is tainted
                        for (int j = 0 j < paramLocals.length j++):
                            AccessPath newAP = manager.getAccessPathFactory().copyWithNewValue(ap,
                                    paramLocals[j], None, False)
                            if (newAP is not None)
                                res.add(newAP)
                        }
                    } else:
                        // Taint the corresponding parameter local in
                        // the callee
                        AccessPath newAP = manager.getAccessPathFactory().copyWithNewValue(ap, paramLocals[i])
                        if (newAP is not None)
                            res.add(newAP)
                    }
                }
            }
        }
        return res
    }
}

    def autoAddZero(self):
        return False

    def getResults(self):
        return self.results

    def getPropagationRules(self):
        return self.propagationRules