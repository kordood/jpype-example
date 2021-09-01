import CastExpr, InstanceOfExpr, LengthExpr, NewArrayExpr, InstanceInvokeExpr
import Stmt, AssignStmt, ReturnStmt, DefinitionStmt
import TypeUtils, BooleanType, ArrayTaintType, RefType, NoneType, PrimType
import Aliasing
import HashSet
import ByReferenceBoolean
import FlowFunctionType
import AccessPath
from ..flowfunction import FlowFunction
from ..flowfunctions import FlowFunctions


class SolverReturnFlowFunction(FlowFunction, FlowFunctions):

    def compute_targets(self, source, d1, callerD1s):
        res = self.computeTargetsInternal(source, callerD1s)
        return self.notifyOutFlowHandlers(self.exitStmt, d1, source, res, FlowFunctionType.ReturnFlowFunction)

    def computeTargetsInternal(self, source, callerD1s):
        if self.manager.getConfig().getStopAfterFirstFlow() and not self.results.isEmpty():
            return None
        if source == self.getZeroValue():
            return None

        if self.taintPropagationHandler is not None:
            self.taintPropagationHandler.notifyFlowIn(self.exitStmt, source, self.manager,
                                                       FlowFunctionType.ReturnFlowFunction)
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
                    ap = self.manager.getAccessPathFactory().copyWithNewValue(newSource.getAccessPath(), leftOp)
                    abs = newSource.deriveNewAbstraction(ap, self.exitStmt)
                    if abs is not None:
                        res.add(abs)
                        if self.aliasing.getAliasingStrategy().requiresAnalysisOnReturn():
                            for d1 in callerD1s:
                                self.aliasing.computeAliases(d1, self.iCallStmt, leftOp, res,
                                                              self.interproceduralCFG().get_method_of(self.callSite),
                                                              abs)

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
                            and not self.manager.getTypeUtils().checkCast(source.getAccessPath(),
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

                    ap = self.manager.getAccessPathFactory().copyWithNewValue(
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

                if self.manager.getTypeUtils().checkCast(source.getAccessPath(), self.thisLocal.getType()):
                    iIExpr = self.iCallStmt.getInvokeExpr()

                    callerBaseLocal = iIExpr.getArg(0) \
                        if self.interproceduralCFG().isReflectiveCallSite(iIExpr) else iIExpr.getBase()
                    ap = self.manager.getAccessPathFactory().copyWithNewValue(
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
