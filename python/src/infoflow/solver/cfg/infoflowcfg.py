import AssignStmt
import FieldRef
import StaticFieldRef
import VirtualInvokeExpr
import RefType
import Scene

# import ExceptionalUnitGraph
# import JimpleBasedInterproceduralCFG

from ...misc.pyenum import PyEnum


class InfoflowCFG:
    MAX_SIDE_EFFECT_ANALYSIS_DEPTH = 25
    MAX_STATIC_USE_ANALYSIS_DEPTH = 50

    StaticFieldUse = PyEnum( 'Unknown', 'Unused', 'Read', 'Write', 'ReadWrite' )

    def __init__(self, delegate):
        #( JimpleBasedInterproceduralCFG( True, True ) )
        self.delegate = delegate
        self.staticFieldUses = dict()
        self.staticFieldUses = dict()

        self.unitToPostdominator = list()
        self.methodToUsedLocals = list()
        self.methodToWrittenLocals = list()

    def getPostdominatorOf(self, u):
        return self.unitToPostdominator.append( u )

    def getMethodOf(self, u):
        return self.delegate.getMethodOf( u )

    def getSuccsOf(self, u):
        return self.delegate.getSuccsOf( u )

    def isExitStmt(self, u):
        return self.delegate.isExitStmt( u )

    def isStartPoint(self, u):
        return self.delegate.isStartPoint( u )

    def isFallThroughSuccessor(self, u, succ):
        return self.delegate.isFallThroughSuccessor( u, succ )

    def isBranchTarget(self, u, succ):
        return self.delegate.isBranchTarget( u, succ )

    def getStartPointsOf(self, m):
        return self.delegate.getStartPointsOf( m )

    def isCallStmt(self, u):
        return self.delegate.isCallStmt( u )

    def allNonCallStartNodes(self):
        return self.delegate.allNonCallStartNodes()

    def getCalleesOfCallAt(self, u):
        return self.delegate.getCalleesOfCallAt( u )

    def getCallersOf(self, m):
        return self.delegate.getCallersOf( m )

    def getReturnSitesOfCallAt(self, u):
        return self.delegate.getReturnSitesOfCallAt( u )

    def getCallsFromWithin(self, m):
        return self.delegate.getCallsFromWithin( m )

    def getPredsOf(self, u):
        return self.delegate.getPredsOf( u )

    def getEndPointsOf(self, m):
        return self.delegate.getEndPointsOf( m )

    def getPredsOfCallAt(self, u):
        return self.delegate.getPredsOf( u )

    def allNonCallEndNodes(self):
        return self.delegate.allNonCallEndNodes()

    def getOrCreateUnitGraph(self, m):
        return self.delegate.getOrCreateUnitGraph( m )

    def getParameterRefs(self, m):
        return self.delegate.getParameterRefs( m )

    def isReturnSite(self, n):
        return self.delegate.isReturnSite( n )

    def isStaticFieldRead(self, method, variable):
        use = self.checkStaticFieldUsed( method, variable )
        return use == self.StaticFieldUse.Read or use == self.StaticFieldUse.ReadWrite or use == self.StaticFieldUse.Unknown

    def isStaticFieldUsed(self, method, variable):
        use = self.checkStaticFieldUsed( method, variable )
        return use == self.StaticFieldUse.Write or use == self.StaticFieldUse.ReadWrite or use == self.StaticFieldUse.Unknown

    def checkStaticFieldUsed(self, smethod, variable):
        if not smethod.isConcrete() or not smethod.hasActiveBody():
            return self.StaticFieldUse.Unused

        workList = list()
        workList.append( smethod )
        tempUses = dict()

        processedMethods = 0
        while len( workList ) > 0:
            method = workList.pop( len( workList ) - 1 )
            processedMethods += 1

            if not method.hasActiveBody():
                continue

            if processedMethods > self.MAX_STATIC_USE_ANALYSIS_DEPTH:
                return self.StaticFieldUse.Unknown

            hasInvocation = False
            reads = False
            writes = False

            entry = self.staticFieldUses.get( method )
            if entry is not None:
                b = entry.get( variable )
                if b is not None and b != self.StaticFieldUse.Unknown:
                    tempUses[method] = b
                    continue

            oldUse = tempUses.get( method )

            for u in method.active_body.units:
                if isinstance( u, AssignStmt ):
                    assign = u

                    if isinstance( assign.getLeftOp(), StaticFieldRef ):
                        sf = assign.getLeftOp().getField()
                        self.registerStaticVariableUse( method, sf, self.StaticFieldUse.Write )
                        if variable == sf:
                            writes = True

                    if isinstance( assign.getRightOp(), StaticFieldRef ):
                        sf = assign.getRightOp().getField()
                        self.registerStaticVariableUse( method, sf, self.StaticFieldUse.Read )
                        if variable == sf:
                            reads = True

                if u.containsInvokeExpr():
                    for edge in Scene.v().getCallGraph().edgesOutOf( u ):
                        callee = edge.getTgt().method()
                        if callee.isConcrete():

                            calleeUse = tempUses.get( callee )
                            if calleeUse is None:

                                if not hasInvocation:
                                    workList.append( method )

                                workList.append( callee )
                                hasInvocation = True
                            else:
                                reads |= calleeUse == self.StaticFieldUse.Read or calleeUse == self.StaticFieldUse.ReadWrite
                                writes |= calleeUse == self.StaticFieldUse.Write or calleeUse == self.StaticFieldUse.ReadWrite

            fieldUse = self.StaticFieldUse.Unused
            if reads and writes:
                fieldUse = self.StaticFieldUse.ReadWrite
            elif reads:
                fieldUse = self.StaticFieldUse.Read
            elif writes:
                fieldUse = self.StaticFieldUse.Write

            if fieldUse == oldUse:
                continue
            tempUses[method] = fieldUse

        for key, value in tempUses.items():
            self.registerStaticVariableUse( key, variable, value )

        outerUse = tempUses.get( smethod )
        return self.StaticFieldUse.Unknown if outerUse is None else outerUse

    def registerStaticVariableUse(self, method, variable, fieldUse):
        entry = self.staticFieldUses.get( method )
        if entry is None:
            entry = dict()
            self.staticFieldUses[method] = entry
            entry[variable] = fieldUse
            return

        oldUse = entry.get( variable )
        if oldUse is None:
            entry[variable] = fieldUse
            return

        newUse = None
        if oldUse == self.StaticFieldUse.Unknown:
            pass
        elif oldUse == self.StaticFieldUse.Unused:
            pass
        elif oldUse == self.StaticFieldUse.ReadWrite:
            newUse = fieldUse
        elif oldUse == self.StaticFieldUse.Read:
            newUse = oldUse if (fieldUse == self.StaticFieldUse.Read) else self.StaticFieldUse.ReadWrite
        elif oldUse == self.StaticFieldUse.Write:
            newUse = oldUse if (fieldUse == self.StaticFieldUse.Write) else self.StaticFieldUse.ReadWrite
        else:
            raise RuntimeError( "Invalid field use" )
        entry[variable] = newUse

    def hasSideEffects(self, method, runList=None, depth=0):
        if runList is None:
            runList = list()

        if not method.hasActiveBody():
            return False

        if not runList.add( method ):
            return False

        hasSideEffects = self.staticFieldUses.get( method )
        if hasSideEffects is not None:
            return hasSideEffects

        if depth > self.MAX_SIDE_EFFECT_ANALYSIS_DEPTH:
            return True

        for u in method.active_body.units:
            if isinstance( u, AssignStmt ):
                assign = u

                if isinstance( assign.getLeftOp(), FieldRef ):
                    self.staticFieldUses[method] = True
                    return True

            if u.containsInvokeExpr():
                for edge in Scene.v().getCallGraph().edgesOutOf( u ):
                    depth += 1
                    if self.hasSideEffects( edge.getTgt().method(), runList, depth ):
                        return True

        self.staticFieldUses[method] = False
        return False

    """
    NOT YET
    def notifyMethodChanged(self, m):
        if isinstance( self.delegate, JimpleBasedInterproceduralCFG ):
            self.delegate.initializeUnitToOwner( m )
    """

    def methodReadsValue(self, m, v):
        self.methodToUsedLocals.append( m )
        reads = m['value']
        if reads is not None:
            for l in reads:
                if l == v:
                    return True
        return False

    def methodWritesValue(self, m, v):
        self.methodToWrittenLocals.append( m )
        writes = m['value']
        if writes is not None:
            for l in writes:
                if l == v:
                    return True
        return False

    def isExceptionalEdgeBetween(self, u1, u2):
        m1 = self.getMethodOf( u1 )
        m2 = self.getMethodOf( u2 )
        if m1 != m2:
            raise RuntimeError( "Exceptional edges are only supported inside the same method" )
        ug1 = self.getOrCreateUnitGraph( m1 )

        """
        NOT YET
        if not isinstance( ug1, ExceptionalUnitGraph ):
            return False
        """

        eug = ug1
        if not eug.getExceptionalSuccsOf( u1 ).contains( u2 ):
            return False

        dests = eug.getExceptionDests( u1 )
        if dests is not None and not dests.isEmpty():
            ts = Scene.v().getDefaultThrowAnalysis().mightThrow( u1 )
            if ts is not None:
                hasTraps = False
                for dest in dests:
                    trap = dest.getTrap()
                    if trap is not None:
                        hasTraps = True
                        if not ts.catchableAs( trap.getException().getType() ):
                            return False

                if not hasTraps:
                    return False
        return True

    def isReachable(self, u):
        return self.delegate.isReachable( u )

    def isExecutorExecute(self, ie, dest):
        if ie is None or dest is None:
            return False

        ieMethod = ie.getMethod()
        if not ieMethod.name == "execute" and not ieMethod.name == "doPrivileged":
            return False

        ieSubSig = ieMethod.getSubSignature()
        calleeSubSig = dest.getSubSignature()

        if ieSubSig == "execute(java.lang.Runnable)" and calleeSubSig == "run()":
            return True

        if dest.name == "run"  and dest.getParameterCount() == 0 and isinstance( dest.getReturnType(), RefType ):
            if ieSubSig == "java.lang.Object doPrivileged(java.security.PrivilegedAction)":
                return True
            if ieSubSig == "java.lang.Object doPrivileged(java.security.PrivilegedAction,"\
                    + "java.security.AccessControlContext)":
                return True
            if ieSubSig == "java.lang.Object doPrivileged(java.security.PrivilegedExceptionAction)":
                return True
            if ieSubSig == "java.lang.Object doPrivileged(java.security.PrivilegedExceptionAction,"\
                    + "java.security.AccessControlContext)":
                return True
        return False

    def getOrdinaryCalleesOfCallAt(self, u):
        iexpr = u.getInvokeExpr()

        originalCallees = self.getCalleesOfCallAt( u )
        callees = list( len( originalCallees ) )
        for sm in originalCallees:
            if not sm.isStaticInitializer() and not self.isExecutorExecute( iexpr, sm ):
                callees.add( sm )
        return callees

    def isReflectiveCallSite(self, u, iexpr=None):
        if iexpr is None:
            if self.isCallStmt( u ):
                iexpr = u.getInvokeExpr()
                return self.isReflectiveCallSite( iexpr )
            return False
        else:
            if isinstance( iexpr, VirtualInvokeExpr ):
                viexpr = iexpr
                if isinstance( viexpr.getBase().getType(), RefType ):
                    if (viexpr.getBase().getType()).getSootClass().name == "java.lang.reflect.Method":
                        if viexpr.getMethod().name == "invoke":
                            return True
            return False

    def purge(self):
        self.staticFieldUses.clear()
        self.staticFieldUses.clear()

        self.methodToUsedLocals.clear()
        self.methodToWrittenLocals.clear()
        self.unitToPostdominator.clear()
