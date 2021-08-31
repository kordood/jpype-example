import CastExpr, InstanceOfExpr, LengthExpr, NewArrayExpr, InstanceInvokeExpr
import Collections
import HashSet
import ByReferenceBoolean
import FlowFunctionType
from ..flowfunction import FlowFunction

class SolverCallToReturnFlowFunction(FlowFunction):

    def compute_targets(self, d1, source):
        res = self.computeTargetsInternal( d1, source )
        return self.notifyOutFlowHandlers( self.call, d1, source, res, FlowFunctionType.CallToReturnFlowFunction )

    def computeTargetsInternal(self, d1, source):
        if self.manager.getConfig().getStopAfterFirstFlow() and not self.results.isEmpty():
            return None

        if self.taintPropagationHandler is not None:
            self.taintPropagationHandler.notifyFlowIn( self.call, source, self.manager,
                                                       FlowFunctionType.CallToReturnFlowFunction )

        newSource = None
        if not source.isAbstractionActive() \
                and call == source.getActivationUnit() \
                or self.isCallSiteActivatingTaint( self.call, source.getActivationUnit() ):
            newSource = source.getActiveCopy()
        else:
            newSource = source

        killSource = ByReferenceBoolean()
        killAll = ByReferenceBoolean()
        res = self.propagationRules.applyCallToReturnFlowFunction( d1, newSource, self.iCallStmt,
                                                                   killSource, killAll, True )
        if killAll.value:
            return None
        passOn = not killSource.value

        if source == self.getZeroValue():
            return Collections.emptySet() if res == None or res.isEmpty() else res

        if res == None:
            res = HashSet()

        if newSource.getTopPostdominator() is not None \
                and newSource.getTopPostdominator().getUnit() is None:
            return Collections.singleton( newSource )

        if newSource.getAccessPath().isStaticFieldRef():
            passOn = False

        if passOn \
                and isinstance( self.invExpr, InstanceInvokeExpr ) \
                and (self.manager.getConfig().getInspectSources() or not self.isSource) \
                and (self.manager.getConfig().getInspectSinks() or not self.isSink) \
                and newSource.getAccessPath().isInstanceFieldRef() \
                and (self.hasValidCallees \
                     or (self.taintWrapper is not None and self.taintWrapper.isExclusive( self.iCallStmt, newSource ))):

            callees = self.interproceduralCFG().getCalleesOfCallAt( self.call )
            allCalleesRead = not callees.isEmpty()
            for callee in callees:
                if callee.isConcrete() and callee.hasActiveBody():
                    calleeAPs = self.mapAccessPathToCallee( callee, self.invExpr, None, None, source.getAccessPath() )
                    if calleeAPs is not None:
                        for ap in calleeAPs:
                            if ap is not None:
                                if not self.interproceduralCFG().methodReadsValue( callee, ap.getPlainValue() ):
                                    allCalleesRead = False
                                    break

                if self.isExcluded( callee ):
                    allCalleesRead = False
                    break

            if allCalleesRead:
                if self.aliasing.mayAlias( self.invExpr.getBase(), newSource.getAccessPath().getPlainValue() ):
                    passOn = False
                if passOn:
                    for i in range( self.callArgs.length ):
                        if self.aliasing.mayAlias( self.callArgs[i], newSource.getAccessPath().getPlainValue() ):
                            passOn = False
                            break
                if newSource.getAccessPath().isStaticFieldRef():
                    passOn = False

        if source.getAccessPath().isStaticFieldRef():
            if not self.interproceduralCFG().isStaticFieldUsed( callee, source.getAccessPath().getFirstField() ):
                passOn = True

        passOn |= source.getTopPostdominator() is not None or source.getAccessPath().isEmpty()
        if passOn:
            if newSource != self.getZeroValue():
                res.add( newSource )

        if callee.isNative():
            for callVal in self.callArgs:
                if callVal == newSource.getAccessPath().getPlainValue():
                    nativeAbs = self.ncHandler.getTaintedValues( self.iCallStmt, newSource, self.callArgs )
                    if nativeAbs is not None:
                        res.addAll( nativeAbs )

                        for abs in nativeAbs:
                            if abs.getAccessPath().isStaticFieldRef() \
                                    or self.aliasing.canHaveAliases( self.iCallStmt,
                                                                abs.getAccessPath().getCompleteValue(),
                                                                abs ):
                                self.aliasing.computeAliases( d1, self.iCallStmt,
                                                         abs.getAccessPath().getPlainValue(), res,
                                                         self.interproceduralCFG().get_method_of( self.call ), abs )
                    break

        for abs in res:
            if abs != newSource:
                abs.setCorrespondingCallSite( self.iCallStmt )

        return res