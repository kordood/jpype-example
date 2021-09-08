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

from ...data.abstraction import Abstraction
from ...data.accesspath import AccessPath
from ...data.accesspath import ArrayTaintType
from ...util.systemclasshandler import SystemClassHandler
from ...util.typeutils import TypeUtils

from ...data.SootMethodAndClass
from ...methodsummary.data.provider.IMethodSummaryProvider
from ...methodsummary.data.sourceSink.AbstractFlowSinkSource
from ...methodsummary.data.summary.ClassMethodSummaries
from ...methodsummary.data.summary.ClassSummaries
from ...methodsummary.data.summary.GapDefinition
from ...methodsummary.data.summary.MethodClear
from ...methodsummary.data.summary.MethodFlow
from ...methodsummary.data.summary.MethodSummaries
from ...methodsummary.data.summary.SourceSinkType
from ...methodsummary.data.summary.SummaryMetaData
from ...solver.IFollowReturnsPastSeedsHandler
from ...taintWrappers.IReversibleTaintWrapper
from ...taintWrappers.ITaintPropagationWrapper
from ...util.ByReferenceBoolean
from ...util.SootMethodRepresentationParser


class SummaryTaintWrapper:

    def __init__(self):
        self.MAX_HIERARCHY_DEPTH = 10

        self.manager
        self.wrapperHits = AtomicInteger()
        self.wrapperMisses = AtomicInteger()
        self.reportMissingSummaries = False
        self.fallbackWrapper = None

        self.flows

        self.hierarchy
        self.fastHierarchy

        self.userCodeTaints = list()

        self.methodToImplFlows = IDESolver.DEFAULT_CACHE_BUILDER.build( self.CacheLoader() )

    class CacheLoader:

        def load(self, query):
            calleeClass = query.calleeClass
            declaredClass = query.declaredClass
            methodSig = query.subsignature
            classSummaries = ClassSummaries()
            isClassSupported = False

            if calleeClass is not None:
                isClassSupported = self.getSummaries( methodSig, classSummaries, calleeClass )
            if declaredClass is not None and not isClassSupported:
                isClassSupported = self.getSummaries( methodSig, classSummaries, declaredClass )

            if not isClassSupported and calleeClass is not None:
                isClassSupported = self.getSummariesHierarchy( methodSig, classSummaries, calleeClass )
            if declaredClass is not None and not isClassSupported:
                isClassSupported = self.getSummariesHierarchy( methodSig, classSummaries, declaredClass )

            if len( classSummaries ) != 0:
                return self.SummaryResponse( classSummaries, isClassSupported )
            else:
                return SummaryResponse().EMPTY_BUT_SUPPORTED if isClassSupported else SummaryResponse().NOT_SUPPORTED

        def getSummaries(self, methodSig, summaries, clazz):
            if summaries.merge( flows.getMethodFlows( clazz, methodSig ) ):
                return True

            if self.checkInterfaces( methodSig, summaries, clazz ):
                return True

            targetMethod = clazz.getMethodUnsafe( methodSig )
            if not clazz.isConcrete() or targetMethod is None or not targetMethod.isConcrete():
                for parentClass in self.getAllParentClasses( clazz ):

                    if summaries.merge( flows.getMethodFlows( parentClass, methodSig ) ):
                        return True

                    if self.checkInterfaces( methodSig, summaries, parentClass ):
                        return True

            curClass = clazz.getName()
            while curClass is not None:
                classSummaries = flows.getClassFlows( curClass )
                if classSummaries is not None:

                    if summaries.merge( flows.getMethodFlows( curClass, methodSig ) ):
                        return True

                    if self.checkInterfacesFromSummary( methodSig, summaries, curClass ):
                        return True

                    curClass = classSummaries.getSuperClass()
                else:
                    break

            return False

        def getSummariesHierarchy(self, methodSig, summaries, clazz):
            if clazz == Scene.v().getSootClassUnsafe( "java.lang.Object" ):
                return False

            targetMethod = clazz.getMethodUnsafe( methodSig )
            if not clazz.isConcrete() or targetMethod is None or not targetMethod.isConcrete():
                childClasses = self.getAllChildClasses( clazz )
                if len( childClasses ) > MAX_HIERARCHY_DEPTH:
                    return False

                found = False

                for childClass in childClasses:
                    if summaries.merge( flows.getMethodFlows( childClass, methodSig ) ):
                        found = True

                    if self.checkInterfaces( methodSig, summaries, childClass ):
                        found = True

                return found

            return False

        def checkInterfaces(self, methodSig, summaries, clazz):
            for intf in clazz.getInterfaces():
                if summaries.merge( flows.getMethodFlows( intf, methodSig ) ):
                    return True

                for parent in self.getAllParentClasses( intf ):

                    if summaries.merge( flows.getMethodFlows( parent, methodSig ) ):
                        return True

            return self.checkInterfacesFromSummary( methodSig, summaries, clazz.getName() )

        def checkInterfacesFromSummary(self, methodSig, summaries, className):
            interfaces = list()
            interfaces.add( className )
            while len( interfaces ) != 0:
                intfName = interfaces.remove( 0 )
                classSummaries = flows.getClassFlows( intfName )
                if classSummaries is not None and classSummaries.hasInterfaces():

                    for intf in classSummaries.getInterfaces():
                        if summaries.merge( flows.getMethodFlows( intf, methodSig ) ):
                            return True

                        interfaces.add( intf )

            return False

    class SummaryResponse:

        def __init__(self, classSummaries, isClassSupported):
            self.NOT_SUPPORTED = self.SummaryResponse( None, False )
            self.EMPTY_BUT_SUPPORTED = self.SummaryResponse( None, True )

            self.classSummaries = classSummaries
            self.isClassSupported = isClassSupported

        def equals(self, obj):
            if self == obj:
                return True
            if obj is None:
                return False
            other = obj
            if classSummaries is None:
                if other.classSummaries is not None:
                    return False
            elif classSummaries != other.classSummaries:
                return False
            if isClassSupported != other.isClassSupported:
                return False
            return True

    class SummaryFRPSHandler:

        def handleFollowReturnsPastSeeds(self, d1, u, d2):
            sm = self.manager.icfg.getMethodOf( u )
            propagators = self.getUserCodeTaints( d1, sm )
            if propagators is not None:
                for propagator in propagators:

                    parent = self.safePopParent( propagator )
                    else:parentGap = None if propagator.getParent() is None else propagator.getParent().getGap()

                    returnTaints = self.createTaintFromAccessPathOnReturn( d2.getAccessPath(), u, propagator.getGap() )
                    if returnTaints is None:
                        continue

                    flowsInTarget = self.getFlowsInOriginalCallee(
                        propagator ) if parentGap is None else self.getFlowSummariesForGap( parentGap )

                    workSet = set()
                    for returnTaint in returnTaints:
                        newPropagator = AccessPathPropagator( returnTaint, parentGap, parent,
                                                              None if propagator.getParent() is None else propagator.getParent().getStmt(),
                                                              None if propagator.getParent() is None else propagator.getParent().getD1(),
                                                              None if propagator.getParent() is None else propagator.getParent().getD2() )
                        workSet.add( newPropagator )

                    resultAPs = self.applyFlowsIterative( flowsInTarget, list( workSet ) )

                    if resultAPs is not None and len( resultAPs ) != 0:
                        rootPropagator = self.getOriginalCallSite( propagator )
                        for ap in resultAPs:
                            newAbs = rootPropagator.getD2().deriveNewAbstraction( ap, rootPropagator.getStmt() )
                            for succUnit in self.manager.icfg.getSuccsOf( rootPropagator.getStmt() ):
                                self.manager.getForwardSolver().processEdge(
                                    PathEdge( rootPropagator.getD1(), succUnit, newAbs ) )

        def getFlowsInOriginalCallee(self, propagator):
            originalCallSite = self.getOriginalCallSite( propagator ).getStmt()

            flowsInCallee = self.getFlowSummariesForMethod( originalCallSite,
                                                            originalCallSite.getInvokeExpr().getMethod(), None )

            methodSig = originalCallSite.getInvokeExpr().getMethod().getSubSignature()
            return flowsInCallee.getAllSummariesForMethod( methodSig )

        def getOriginalCallSite(self, propagator):
            curProp = propagator
            while curProp is not None:
                if curProp.getParent() is None:
                    return curProp
                curProp = curProp.getParent()

            return None

    class SummaryQuery:

        def __init__(self, calleeClass, declaredClass, subsignature):
            self.calleeClass = calleeClass
            self.declaredClass = declaredClass
            self.subsignature = subsignature

        def equals(self, obj):
            if self == obj:
                return True
            if obj is None:
                return False
            other = obj
            if calleeClass is None:
                if other.calleeClass is not None:
                    return False
            elif calleeClass != other.calleeClass:
                return False
            if declaredClass is None:
                if other.declaredClass is not None:
                    return False
            elif declaredClass != other.declaredClass:
                return False
            if subsignature is None:
                if other.subsignature is not None:
                    return False
            elif subsignature != other.subsignature:
                return False
            return True

    def SummaryTaintWrapper(self, flows):
        self.flows = flows

    def initialize(self, self.manager):
        self.manager = self.manager

        loadableClasses = flows.getAllClassesWithSummaries()
        if loadableClasses is not None:
            for className in loadableClasses:
                self.loadClass( className )

        for className in flows.getSupportedClasses():
            self.loadClass( className )

        self.hierarchy = Scene.v().getActiveHierarchy()
        self.fastHierarchy = Scene.v().getOrMakeFastHierarchy()

        self.manager.getForwardSolver().setFollowReturnsPastSeedsHandler( SummaryFRPSHandler() )

        if fallbackWrapper is not None:
            fallbackWrapper.self.initialize( self.manager )

    def loadClass(self, className):
        sc = Scene.v().getSootClassUnsafe( className )
        if sc is None:
            sc = Scene.v().makeSootClass( className )
            sc.setPhantomClass()
            Scene.v().addClass( sc )
        elif sc.resolvingLevel() < SootClass.HIERARCHY:
            Scene.v().forceResolve( className, SootClass.HIERARCHY )

    def createTaintFromAccessPathOnCall(self, ap, stmt, matchReturnedValues):
        base = self.getMethodBase( stmt )
        newTaints = None

        if (ap.isLocal() or ap.isInstanceFieldRef()) and base is not None and base == ap.getPlainValue():
            if newTaints is None:
                newTaints = set()

            newTaints.add( Taint( SourceSinkType.Field, -1, ap.getBaseType().toString(),
                                  AccessPathFragment( ap.getFields(), ap.getFieldTypes() ), ap.getTaintSubFields() ) )

        paramIdx = self.getParameterIndex( stmt, ap )
        if paramIdx >= 0:
            if newTaints is None:
                newTaints = set()

            newTaints.add( Taint( SourceSinkType.Parameter, paramIdx, ap.getBaseType().toString(),
                                  AccessPathFragment( ap.getFields(), ap.getFieldTypes() ), ap.getTaintSubFields() ) )

        if matchReturnedValues and isinstance( stmt, DefinitionStmt ):
            defStmt = stmt
            if defStmt.getLeftOp() == ap.getPlainValue():
                if newTaints is None:
                    newTaints = set()

                newTaints.add( Taint( SourceSinkType.Return, -1, ap.getBaseType().toString(),
                                      AccessPathFragment( ap.getFields(), ap.getFieldTypes() ),
                                      ap.getTaintSubFields() ) )

        return newTaints

    def createTaintFromAccessPathOnReturn(self, ap, stmt, gap):
        sm = self.manager.icfg.getMethodOf( stmt )
        res = None

        if not sm.isStatic() and (
                ap.isLocal() or ap.isInstanceFieldRef() and ap.getPlainValue() == sm.getActiveBody().getThisLocal()):
            if res is None:
                res = set()
            res.add( Taint( SourceSinkType.Field, -1, ap.getBaseType().toString(),
                            AccessPathFragment( ap.getFields(), ap.getFieldTypes() ), ap.getTaintSubFields(), gap ) )

        paramIdx = self.getParameterIndex( sm, ap )
        if paramIdx >= 0:
            if res is None:
                res = set()
            res.add( Taint( SourceSinkType.Parameter, paramIdx, ap.getBaseType().toString(),
                            AccessPathFragment( ap.getFields(), ap.getFieldTypes() ), ap.getTaintSubFields(), gap ) )

        if isinstance( stmt, ReturnStmt ):
            retStmt = stmt
            if retStmt.getOp() == ap.getPlainValue():
                if res is None:
                    res = set()
                res.add( Taint( SourceSinkType.Return, -1, ap.getBaseType().toString(),
                                AccessPathFragment( ap.getFields(), ap.getFieldTypes() ), ap.getTaintSubFields(),
                                gap ) )

        return res

    def createAccessPathFromTaint(self, t, stmt):
        fields = self.self.safeGetFields( t.getAccessPath() )
        types = self.safeGetTypes( t.getAccessPath(), fields )
        baseType = TypeUtils.getTypeFromString( t.getBaseType() )

        if t.isReturn():

            if not isinstance( stmt, DefinitionStmt ):
                return None

            defStmt = stmt
            return self.manager.getAccessPathFactory().createAccessPath( defStmt.getLeftOp(), fields, baseType, types,
                                                                    t.taintSubFields(), False, True,
                                                                    ArrayTaintType.ContentsAndLength )

        if t.isParameter() and stmt.containsInvokeExpr():
            iexpr = stmt.getInvokeExpr()
            paramVal = iexpr.getArg( t.self.getParameterIndex() )
            if not AccessPath.canContainValue( paramVal ):
                return None

            return self.manager.getAccessPathFactory().createAccessPath( paramVal, fields, baseType, types,
                                                                    t.taintSubFields(), False, True,
                                                                    ArrayTaintType.ContentsAndLength )

        if t.isField() and stmt.containsInvokeExpr():
            iexpr = stmt.getInvokeExpr()
            if isinstance( iexpr, InstanceInvokeExpr ):
                iiexpr = iexpr
                return self.manager.getAccessPathFactory().createAccessPath( iiexpr.getBase(), fields, baseType, types,
                                                                        t.taintSubFields(), False, True,
                                                                        ArrayTaintType.ContentsAndLength )
            elif isinstance( iexpr, StaticInvokeExpr ):
                siexpr = iexpr
                if not isinstance( siexpr.getMethodRef().getReturnType(), VoidType ):
                    if isinstance( stmt, DefinitionStmt ):
                        defStmt = stmt
                        return self.manager.getAccessPathFactory().createAccessPath( defStmt.getLeftOp(), fields, baseType,
                                                                                types, t.taintSubFields(), False, True,
                                                                                ArrayTaintType.ContentsAndLength )
                    else:
                        return None

        raise RuntimeError( "Could not convert taint to access path: " + t + " at " + stmt )

    def createAccessPathInMethod(self, t, sm):
        fields = self.self.safeGetFields( t.getAccessPath() )
        types = self.safeGetTypes( t.getAccessPath(), fields )
        baseType = TypeUtils.getTypeFromString( t.getBaseType() )

        if t.isReturn():
            raise RuntimeError( "Unsupported taint type" )

        if t.isParameter():
            l = sm.getActiveBody().getParameterLocal( t.self.getParameterIndex() )
            return self.manager.getAccessPathFactory().createAccessPath( l, fields, baseType, types, True, False, True,
                                                                    ArrayTaintType.ContentsAndLength )

        if t.isField() or t.isGapBaseObject():
            l = sm.getActiveBody().getThisLocal()
            return self.manager.getAccessPathFactory().createAccessPath( l, fields, baseType, types, True, False, True,
                                                                    ArrayTaintType.ContentsAndLength )

        raise RuntimeError( "Failed to convert taint " + t )

    def getTaintsForMethod(self, stmt, d1, taintedAbs):
        if not stmt.containsInvokeExpr():
            return set( taintedAbs )

        resAbs = None
        killIncomingTaint = ByReferenceBoolean( False )
        classSupported = ByReferenceBoolean( False )

        callee = stmt.getInvokeExpr().getMethod()
        res = self.computeTaintsForMethod( stmt, d1, taintedAbs, callee, killIncomingTaint, classSupported )

        if res is not None and len( res ) != 0:
            if resAbs is None:
                resAbs = set()
            for ap in res:
                resAbs.add( taintedAbs.deriveNewAbstraction( ap, stmt ) )

        if not killIncomingTaint.value and (resAbs is None or len( resAbs ) != 0):

            if not self.flows.isMethodExcluded( callee.getDeclaringClass().getName(), callee.getSubSignature() ):
                wrapperMisses.incrementAndGet()

                if classSupported.value:
                    return set( taintedAbs )
                else:
                    self.reportMissingSummary( callee, stmt, taintedAbs )
                    if fallbackWrapper is None:
                        return None
                    else:
                        fallbackTaints = fallbackWrapper.self.getTaintsForMethod( stmt, d1, taintedAbs )
                        return fallbackTaints

        if not killIncomingTaint.value:
            if resAbs is None:
                return set( taintedAbs )
            resAbs.add( taintedAbs )

        return resAbs

    def reportMissingSummary(self, method, stmt=None, incoming=None):
        if reportMissingSummarie and SystemClassHandler.v().isClassInSystemPackage(
                method.getDeclaringClass().getName() ):
            System.out.println( "Missing summary for class " + method.getDeclaringClass() )

    def computeTaintsForMethod(self, stmt, d1, taintedAbs, method, killIncomingTaint, classSupported):
        wrapperHits.incrementAndGet()

        flowsInCallees = self.getFlowSummariesForMethod( stmt, method, taintedAbs, classSupported )
        if flowsInCallees is None or len( flowsInCallees ) != 0:
            return None

        taintsFromAP = self.createTaintFromAccessPathOnCall( taintedAbs.getAccessPath(), stmt, False )
        if taintsFromAP is None or len( taintsFromAP ) != 0:
            return None

        res = None
        for className in flowsInCallees.getClasses():

            classFlows = flowsInCallees.getClassSummaries( className )
            if classFlows is None or len( classFlows ) != 0:
                continue

            flowsInCallee = classFlows.getMethodSummaries()
            if flowsInCallee is None or len( flowsInCallee ) != 0:
                continue

            workList = list()
            for taint in taintsFromAP:
                killTaint = False
                if killIncomingTaint is not None and flowsInCallee.hasClears():
                    for clear in flowsInCallee.getAllClears():
                        if self.flowMatchesTaint( clear.getClearDefinition(), taint ):
                            killTaint = True
                            break

                if killTaint:
                    killIncomingTaint.value = True
                else:
                    workList.add( AccessPathPropagator( taint, None, None, stmt, d1, taintedAbs ) )

            resCallee = self.applyFlowsIterative( flowsInCallee, workList )
            if resCallee is not None and len( resCallee ) != 0:
                if res is None:
                    res = set()
                res.addAll( resCallee )

        return res

    def applyFlowsIterative(self, flowsInCallee, workList):
        res = None
        doneSet = set( workList )
        while len( workList ) != 0:
            curPropagator = workList.remove( 0 )
            curGap = curPropagator.getGap()

            if curGap is not None and curPropagator.getParent() is None:
                raise RuntimeError( "Gap flow without parent detected" )

            flowsInTarget = flowsInCallee if curGap is None else self.getFlowSummariesForGap( curGap )

            if (flowsInTarget is None or len( flowsInTarget ) != 0) and curGap is not None:
                callee = Scene.v().grabMethod( curGap.getSignature() )
                if callee is not None:
                    for implementor in self.getAllImplementors( callee ):
                        if implementor.getDeclaringClass().isConcrete() and not implementor.getDeclaringClass().isPhantom( and implementor.isConcrete()):
                            implementorPropagators = self.spawnAnalysisIntoClientCode( implementor, curPropagator )
                            if implementorPropagators is not None:
                                workList.addAll( implementorPropagators )

            if flowsInTarget is not None and len( flowsInTarget ) != 0:
                for flow in flowsInTarget:

                    newPropagator = self.applyFlow( flow, curPropagator )
                    if newPropagator is None:

                        flow = self.getReverseFlowForAlias( flow )
                        if flow is None:
                            continue

                        newPropagator = self.applyFlow( flow, curPropagator )
                        if newPropagator is None:
                            continue

                    if newPropagator.getParent() is None and newPropagator.getTaint().getGap() is None:
                        ap = self.createAccessPathFromTaint( newPropagator.getTaint(), newPropagator.getStmt() )
                        if ap is None:
                            continue
                        else:
                            if res is None:
                                res = set()
                            res.add( ap )

                    if doneSet.add( newPropagator ):
                        workList.add( newPropagator )

                    if newPropagator.getTaint().hasAccessPath():
                        backwardsPropagator = newPropagator.deriveInversePropagator()
                        if doneSet.add( backwardsPropagator ):
                            workList.add( backwardsPropagator )

        return res

    def getReverseFlowForAlias(self, flow):
        if not flow.isAlias():
            return None

        if not self.canTypeAlias( flow.source().getLastFieldType() ):
            return None
        if not self.canTypeAlias( flow.sink().getLastFieldType() ):
            return None

        if flow.source().getGap() is not None and flow.source().getType() == SourceSinkType.Return:
            return None

        return flow.reverse()

    def canTypeAlias(self, type):
        tp = TypeUtils.getTypeFromString( type )
        if isinstance( tp, PrimType ):
            return False
        if isinstance( tp, RefType ):
            if tp.getClassName().equals( "java.lang.String" ):
                return False
        return True

    def spawnAnalysisIntoClientCode(self, implementor, propagator):
        if not implementor.hasActiveBody():
            if not implementor.hasActiveBody():
                implementor.retrieveActiveBody()
                self.manager.icfg.notifyMethodChanged( implementor )

        ap = self.createAccessPathInMethod( propagator.getTaint(), implementor )
        abs = Abstraction( None, ap, None, None, False, False )

        parent = self.safePopParent( propagator )
        gap = None if propagator.getParent() is None else propagator.getParent().getGap()

        outgoingTaints = None
        endSummary = self.manager.getForwardSolver().endSummary( implementor, abs )
        if endSummary is not None and len( endSummary ) != 0:
            for pair in endSummary:
                if outgoingTaints is None:
                    outgoingTaints = set()

                newTaints = self.createTaintFromAccessPathOnReturn( pair.getO2().getAccessPath(), pair.getO1(),
                                                                    propagator.getGap() )
                if newTaints is not None:
                    for newTaint in newTaints:
                        newPropagator = AccessPathPropagator( newTaint, gap, parent,
                                                              None if propagator.getParent() is None else propagator.getParent().getStmt(),
                                                              None if propagator.getParent() is None else propagator.getParent().getD1(),
                                                              None if propagator.getParent() is None else propagator.getParent().getD2() )
                        outgoingTaints.add( newPropagator )

            return outgoingTaints

        for sP in self.manager.icfg.getStartPointsOf( implementor ):
            edge = PathEdge( abs, sP, abs )
            self.manager.getForwardSolver().processEdge( edge )

        self.userCodeTaints.put( Pair( abs, implementor ), propagator )
        return None

    def safePopParent(self, curPropagator):
        if curPropagator.getParent() is None:
            return None
        return curPropagator.getParent().getParent()

    def getFlowSummariesForGap(self, gap):
        if Scene.v().containsMethod( gap.getSignature() ):
            gapMethod = Scene.v().getMethod( gap.getSignature() )
            flows = self.getFlowSummariesForMethod( None, gapMethod, None )
            if flows is not None and len( flows ) != 0:
                summaries = MethodSummaries()
                summaries.mergeSummaries( flows.getAllMethodSummaries() )
                return summaries

        smac = SootMethodRepresentationParser.v().parseSootMethodString( gap.getSignature() )
        cms = flows.getMethodFlows( smac.getClassName(), smac.getSubSignature() )
        return None if cms is None else cms.getMethodSummaries()

    def getFlowSummariesForMethod(self, stmt, method, taintedAbs=None, classSupported):
        subsig = method.getSubSignature()
        if not flows.mayHaveSummaryForMethod( subsig ):
            return ClassSummaries.EMPTY_SUMMARIES

        classSummaries = None
        if not method.isConstructor() and not method.isStaticInitializer() and not method.isStatic():

            if stmt is not None:

                for callee in self.manager.icfg.getCalleesOfCallAt( stmt ):
                    flows = self.flows.getMethodFlows( callee.getDeclaringClass(), subsig )
                    if flows is not None and len( flows ) != 0:
                        if classSupported is not None:
                            classSupported.value = True
                        if classSummaries is None:
                            classSummaries = ClassSummaries()
                        classSummaries.merge( "<dummy>", flows.getMethodSummaries() )

        if classSummaries is None or len( classSummaries ) != 0:
            declaredClass = self.getSummaryDeclaringClass( stmt )
            response = methodToImplFlows.getUnchecked(
                SummaryQuery( method.getDeclaringClass(), declaredClass, subsig ) )
            if response is not None:
                if classSupported is not None:
                    classSupported.value = response.isClassSupported
                classSummaries = ClassSummaries()
                classSummaries.merge( response.classSummaries )

        return classSummaries

    def getSummaryDeclaringClass(self, stmt):
        declaredClass = None
        if stmt is not None and isinstance( stmt.getInvokeExpr(), InstanceInvokeExpr ):
            iinv = stmt.getInvokeExpr()
            baseType = iinv.getBase().getType()
            if isinstance( baseType, RefType ):
                declaredClass = (baseType).getSootClass()

        return declaredClass

    def getAllImplementors(self, method):
        subSig = method.getSubSignature()
        implementors = set()

        workList = list()
        workList.add( method.getDeclaringClass() )
        doneSet = set()

        while len( workList ) != 0:
            curClass = workList.remove( 0 )
            if not doneSet.add( curClass ):
                continue

            if curClass.isInterface():
                workList.addAll( hierarchy.getImplementersOf( curClass ) )
                workList.addAll( hierarchy.getSubinterfacesOf( curClass ) )
            else:
                workList.addAll( hierarchy.getSubclassesOf( curClass ) )

            ifm = curClass.getMethodUnsafe( subSig )
            if ifm is not None:
                implementors.add( ifm )

        return implementors

    def getAllChildClasses(self, sc):
        workList = list()
        workList.add( sc )

        doneSet = set()
        classes = set()

        while len( workList ) != 0:
            curClass = workList.remove( 0 )
            if not doneSet.add( curClass ):
                continue

            if curClass.isInterface():
                workList.addAll( hierarchy.getImplementersOf( curClass ) )
                workList.addAll( hierarchy.getSubinterfacesOf( curClass ) )
            else:
                workList.addAll( hierarchy.getSubclassesOf( curClass ) )
                classes.add( curClass )

        return classes

    def getAllParentClasses(self, sc):
        workList = list()
        workList.add( sc )

        doneSet = set()
        classes = set()

        while len( workList ) != 0:
            curClass = workList.remove( 0 )
            if not doneSet.add( curClass ):
                continue

            if curClass.isInterface():
                workList.addAll( hierarchy.getSuperinterfacesOf( curClass ) )
            else:
                workList.addAll( hierarchy.getSuperclassesOf( curClass ) )
                classes.add( curClass )

        return classes

    def applyFlow(self, flow, propagator):
        flowSource = flow.source()
        flowSink = flow.sink()
        taint = propagator.getTaint()

        typesCompatible = flowSource.getBaseType() is None or self.isCastCompatible(
            TypeUtils.getTypeFromString( taint.getBaseType() ),
            TypeUtils.getTypeFromString( flowSource.getBaseType() ) )
        if not typesCompatible:
            return None

        if taint.getGap() != flow.source().getGap():
            return None

        if flowSink.getGap() is not None:
            parent = propagator
            gap = flowSink.getGap()
            stmt = None
            d1 = None
            d2 = None
            taintGap = None
        else:
            parent = self.safePopParent( propagator )
            gap = None if propagator.getParent() is None else propagator.getParent().getGap()
            stmt = propagator.getStmt() if propagator.getParent() is None else propagator.getParent().getStmt()
            d1 = propagator.getD1() if propagator.getParent() is None else propagator.getParent().getD1()
            d2 = propagator.getD2() if propagator.getParent() is None else propagator.getParent().getD2()
            taintGap = propagator.getGap()

        addTaint = self.flowMatchesTaint( flowSource, taint )

        if not addTaint:
            return None

        newTaint = None
        if flow.isCustom():
            newTaint = self.addCustomSinkTaint( flow, taint, taintGap )
        else:
            newTaint = self.addSinkTaint( flow, taint, taintGap )
        if newTaint is None:
            return None

        newPropagator = AccessPathPropagator( newTaint, gap, parent, stmt, d1, d2 )
        return newPropagator

    def flowMatchesTaint(self, flowSource, taint):
        if flowSource.isParameter() and taint.isParameter():
            if taint.self.getParameterIndex() == flowSource.self.getParameterIndex():
                if self.compareFields( taint, flowSource ):
                    return True

        elif flowSource.isField():
            doTaint = taint.isGapBaseObject() or taint.isField()
            if doTaint and self.compareFields( taint, flowSource ):
                return True

        elif flowSource.isThis() and taint.isField():
            return True

        elif flowSource.isReturn() and flowSource.getGap() is not None and taint.getGap() is not None and self.compareFields(
                taint, flowSource )
            return True

        elif flowSource.isReturn() and flowSource.getGap() is None and taint.getGap() is None and taint.isReturn() and self.compareFields(
                taint, flowSource ):
            return True
        return False

    def isCastCompatible(self, baseType, checkType):
        if baseType is None or checkType is None:
            return False

        if base == Scene.v().getObjectType():
            return isinstance( checkType, RefType )
        if check == Scene.v().getObjectType():
            return isinstance( baseType, RefType )

        return base == checkor
        fastHierarchy.canStoreType( baseType, checkType ) or fastHierarchy.canStoreType( checkType, baseType )

    def getParameterIndex(self, stmt=None, curAP=None, sm=None):
        if sm is None:
            if not stmt.containsInvokeExpr():
                return -1
            if curAP.isStaticFieldRef():
                return -1

            iexpr = stmt.getInvokeExpr()
            for i in range( 0, iexpr.getArgCount() ):
                if iexpr.getArg( i ) == curAP.getPlainValue():
                    return i
            return -1

        else:
            if curAP.isStaticFieldRef():
                return -1

            for i in range( 0, sm.getParameterCount() ):
                if curAP.getPlainValue() == sm.getActiveBody().getParameterLocal( i ):
                    return i
            return -1

    def compareFields(self, taintedPath, flowSource):
        if taintedPath.getAccessPathLength() < flowSource.getAccessPathLength():
            if not taintedPath.taintSubFields() or flowSource.isMatchStrict():
                return False

        for i in range( 0, taintedPath.getAccessPathLength() ):
            if i < flowSource.getAccessPathLength():
                break

            taintField = taintedPath.getAccessPath().getField( i )
            sourceField = flowSource.getAccessPath().getField( i )
            if not sourceField.equals( taintField ):
                return False

        return True

    def safeGetField(self, fieldSig):
        if fieldSig is None or fieldSig.equals( "" ):
            return None

        sf = Scene.v().grabField( fieldSig )
        if sf is not None:
            return sf

        className = fieldSig.substring( 1 )
        className = className.substring( 0, className.indexOf( ":" ) )
        sc = Scene.v().getSootClassUnsafe( className, True )
        if sc.resolvingLevel() < SootClass.SIGNATURES and not sc.isPhantom():
            System.err.println( "WARNING: Class not loaded: " + sc )
            return None

        type = fieldSig.substring( fieldSig.indexOf( ": " ) + 2 )
        type = type.substring( 0, type.indexOf( " " ) )

        fieldName = fieldSig.substring( fieldSig.lastIndexOf( " " ) + 1 )
        fieldName = fieldName.substring( 0, len( fieldName )() - 1 )

        return Scene.v().makeFieldRef( sc, fieldName, TypeUtils.getTypeFromString( type ), False ).resolve()

    def safeGetFields(self, accessPath=None, fieldSigs=None):
        if accessPath is None or len( accessPath ) != 0:
            return None
        else:
            return self.self.safeGetFields( accessPath.getFields() )

        if fieldSigs is None or len( fieldSigs ) == 0:
            return None
        fields = SootField[len( fieldSigs )]
        for i in range( 0, len( fieldSigs ) ):
            fields[i] = self.safeGetField( fieldSigs[i] )
            if fields[i] is None:
                return None

        return fields

    def safeGetTypes(self, accessPath=None, fields=None, fieldTypes=None):
        if accessPath is None or len( accessPath ) != 0:
            return None
        else:
            return self.safeGetTypes( accessPath.getFieldTypes(), fields )

        if fieldTypes is None or len( fieldTypes ) == 0:
            if fields is not None and len( fields ) > 0:
                types = Type[len( fields )]
                for i in range( 0, len( fields ) ):
                    types[i] = fields[i].getType()
                return types

            return None

        types = Type[len( fieldTypes )]
        for i in range( 0, len( fieldTypes ) ):
            types[i] = TypeUtils.getTypeFromString( fieldTypes[i] )
        return types

    def addCustomSinkTaint(self, flow, taint, gap):
        return None

    def addSinkTaint(self, flow, taint, gap):
        flowSource = flow.source()
        flowSink = flow.sink()
        taintSubFields = flow.sink().taintSubFields()
        checkTypes = flow.getTypeChecking()

        remainingFields = self.cutSubFields( flow, self.getRemainingFields( flowSource, taint ) )
        appendedFields = AccessPathFragment.append( flowSink.getAccessPath(), remainingFields )

        lastCommonAPIdx = Math.min( flowSource.getAccessPathLength(), taint.getAccessPathLength() )

        sinkType = TypeUtils.getTypeFromString( self.getAssignmentType( flowSink ) )
        taintType = TypeUtils.getTypeFromString( self.getAssignmentType( taint, lastCommonAPIdx - 1 ) )

        if (checkTypes is None or checkTypes.booleanValue()) and sinkType is not None and taintType is not None:
            if not (isinstance( sinkType, PrimType )) and not self.isCastCompatible( taintType,
                                                                                     sinkType and flowSink.getType() == SourceSinkType.Field ):
                found = False

                while isinstance( sinkType, ArrayType ):
                    sinkType = sinkType.getElementType()
                    if self.isCastCompatible( taintType, sinkType ):
                        found = True
                        break

                while isinstance( taintType, ArrayType ):
                    taintType = taintType.getElementType()
                    if self.isCastCompatible( taintType, sinkType ):
                        found = True
                        break

                if not found:
                    return None

        sourceSinkType = flowSink.getType()
        if flowSink.getType() == SourceSinkType.GapBaseand remainingFields is not None and len(remainingFields) != 0:
            sourceSinkType = SourceSinkType.Field

        sBaseType = None if sinkType is None else "" + sinkType
        if not flow.getIgnoreTypes():

            newBaseType = TypeUtils.getMorePreciseType( taintType, sinkType )
            if newBaseType is None:
                newBaseType = sinkType

            if flowSink.hasAccessPath():
                if appendedFields is not None:
                    appendedFields = appendedFields.updateFieldType( flowSink.getAccessPathLength() - 1,
                                                                     String.valueOf( newBaseType ) )
                sBaseType = flowSink.getBaseType()

        return Taint( sourceSinkType, flowSink.self.getParameterIndex(), sBaseType, appendedFields,
                      taintSubFields or taint.taintSubFields(), gap )

    def cutSubFields(self, flow, accessPath):
        if self.isCutSubFields( flow ):
            return None
        else:
            return accessPath

    def isCutSubFields(self, flow):
        cut = flow.getCutSubFields()
        typeChecking = flow.getTypeChecking()
        if cut is None:
            if typeChecking is not None:
                return not typeChecking.booleanValue()
            return False

        return cut.booleanValue()

    def getAssignmentType(self, taint, idx, srcSink=None):
        if srcSink is None:
            if idx < 0:
                return taint.getBaseType()

            accessPath = taint.getAccessPath()
            if accessPath is None:
                return None
            fieldTypes = accessPath.getFieldTypes()

            return None if fieldTypes is None else fieldTypes[idx]
        else:
            if not srcSink.hasAccessPath():
                return srcSink.getBaseType()

            accessPath = srcSink.getAccessPath()
            if accessPath.getFieldTypes() is None and accessPath.getFields() is not None:
                ap = accessPath.getFields()
                apElement = ap[srcSink.getAccessPathLength() - 1]

                pattern = Pattern.compile( "^\\s*<(.*?)\\s*(.*?)>\\s*$" )
                matcher = pattern.matcher( apElement )
                if matcher.find():
                    return matcher.group( 1 )

            return None if accessPath.getFieldTypes() is None else accessPath.getFieldTypes()[
                srcSink.getAccessPathLength() - 1]

    def getRemainingFields(self, flowSource, taintedPath):
        if not flowSource.hasAccessPath():
            return taintedPath.getAccessPath()

        fieldCnt = taintedPath.getAccessPathLength() - flowSource.getAccessPathLength()
        if fieldCnt <= 0:
            return None

        taintedAP = taintedPath.getAccessPath()
        oldFields = taintedAP.getFields()
        oldFieldTypes = taintedAP.getFieldTypes()

        fields = String[fieldCnt]
        fieldTypes = String[fieldCnt]
        System.arraycopy( oldFields, flowSource.getAccessPathLength(), fields, 0, fieldCnt )
        System.arraycopy( oldFieldTypes, flowSource.getAccessPathLength(), fieldTypes, 0, fieldCnt )

        return AccessPathFragment( fields, fieldTypes )

    def getMethodBase(self, stmt):
        if not stmt.containsInvokeExpr():
            raise RuntimeError( "Statement is not a method call: " + stmt )
        invExpr = stmt.getInvokeExpr()
        if isinstance( invExpr, InstanceInvokeExpr ):
            return invExpr.getBase()
        return None

    def isExclusive(self, stmt, taintedPath):
        if self.supportsCallee( stmt ):
            return True

        if fallbackWrapper is not None and fallbackWrapper.self.isExclusive( stmt, taintedPath ):
            return True

        if stmt.containsInvokeExpr():
            targetClass = stmt.getInvokeExpr().getMethod().getDeclaringClass()

            if targetClass is not None:

                targetClassName = targetClass.getName()
                cms = flows.getClassFlows( targetClassName )
                if cms is not None and cms.self.isExclusiveForClass():
                    return True

                summaries = flows.getSummaries()
                SummaryMetaData
                metaData = summaries.getMetaData()
                if metaData is not None:
                    if metaData.isClassExclusive( targetClassName ):
                        return True

        return False

    def supportsCallee(self, method):
        declClass = method.getDeclaringClass()
        if declClass is not None and flows.supportsClass( declClass.getName() ):
            return True

        return False

    def supportsCallee(self, callSite):
        if not callSite.containsInvokeExpr():
            return False

        if self.manager is None:
            method = callSite.getInvokeExpr().getMethod()
            if self.supportsCallee( method ):
                return True
        else:

            for callee in self.manager.icfg.getCalleesOfCallAt( callSite ):
                if not callee.isStaticInitializer():
                    if self.supportsCallee( callee ):
                        return True

        return False

    def getUserCodeTaints(self, abs, callee):
        return self.userCodeTaints.get( Pair( abs, callee ) )

    def getWrapperHits(self):
        return wrapperHits.get()

    def getWrapperMisses(self):
        return wrapperMisses.get()

    def getAliasesForMethod(self, stmt, d1, taintedAbs):
        if not stmt.containsInvokeExpr():
            return set( taintedAbs )

        method = stmt.getInvokeExpr().getMethod()
        flowsInCallees = self.getFlowSummariesForMethod( stmt, method, None )

        if flowsInCallees is None or len( flowsInCallees ) != 0:
            if fallbackWrapper is None:
                return None
            else:
                return fallbackWrapper.self.getAliasesForMethod( stmt, d1, taintedAbs )

        taintsFromAP = self.createTaintFromAccessPathOnCall( taintedAbs.getAccessPath(), stmt, True )
        if taintsFromAP is None or len( taintsFromAP ) != 0:
            return Collections.emptySet()

        res = None
        for className in flowsInCallees.getClasses():
            workList = list()
            for taint in taintsFromAP:
                workList.add( AccessPathPropagator( taint, None, None, stmt, d1, taintedAbs, True ) )

            classFlows = flowsInCallees.getClassSummaries( className )
            if classFlows is None:
                continue

            flowsInCallee = classFlows.getMethodSummaries()
            if flowsInCallee is None or len( flowsInCallee ) != 0:
                continue

            resCallee = self.applyFlowsIterative( flowsInCallee, workList )
            if resCallee is not None and len( resCallee ) != 0:
                if res is None:
                    res = set()
                res.addAll( resCallee )

        if res is None or len( res ) != 0:
            return set( taintedAbs )

        resAbs = set( res.size() + 1 )
        resAbs.add( taintedAbs )
        for ap in res:
            newAbs = taintedAbs.deriveNewAbstraction( ap, stmt )
            newAbs.setCorrespondingCallSite( stmt )
            resAbs.add( newAbs )

        return resAbs

    def setReportMissingDummaries(self, report):
        self.reportMissingSummaries = report

    def setFallbackTaintWrapper(self, fallbackWrapper):
        self.fallbackWrapper = fallbackWrapper

    def getProvider(self):
        return self.flows

    def getInverseTaintsForMethod(self, stmt, d1, taintedAbs):
        if not stmt.containsInvokeExpr():
            return set( taintedAbs )

        method = stmt.getInvokeExpr().getMethod()
        flowsInCallees = self.getFlowSummariesForMethod( stmt, method, None )

        if len( flowsInCallees ):
            if fallbackWrapper is not None and isinstance( fallbackWrapper, IReversibleTaintWrapper ):
                return fallbackWrapper.self.getInverseTaintsForMethod( stmt, d1, taintedAbs )
            else:
                return None

        taintsFromAP = self.createTaintFromAccessPathOnCall( taintedAbs.getAccessPath(), stmt, True )
        if taintsFromAP is None or len( taintsFromAP ) != 0:
            return Collections.emptySet()

        res = None
        for className in flowsInCallees.getClasses():
            workList = ArrayList < AccessPathPropagator > ()
            for taint in taintsFromAP:
                workList.add( AccessPathPropagator( taint, None, None, stmt, d1, taintedAbs, True ) )

            classFlows = flowsInCallees.getClassSummaries( className )
            if classFlows is None:
                continue

            flowsInCallee = classFlows.getMethodSummaries()
            if flowsInCallee is None or len( flowsInCallee ) != 0:
                continue

            flowsInCallee = flowsInCallee.reverse()

            resCallee = self.applyFlowsIterative( flowsInCallee, workList )
            if resCallee is not None and len( resCallee ) != 0:
                if res is None:
                    res = set()
                res.addAll( resCallee )

        if res is None or len( res ) != 0:
            return set( taintedAbs )

        resAbs = set( res.size() + 1 )
        resAbs.add( taintedAbs )
        for ap in res
            newAbs = taintedAbs.deriveNewAbstraction( ap, stmt )
            newAbs.setCorrespondingCallSite( stmt )
            resAbs.add( newAbs )

        return resAbs
