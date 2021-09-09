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

from ...data.abstraction import Abstraction
from ...data.accesspath import AccessPath
from ...data.accesspath import ArrayTaintType
from ...util.systemclasshandler import SystemClassHandler
from ...util.typeutils import TypeUtils

from ...data.summary.classsummaries import ClassSummaries
from ...data.summary.methodsummaries import MethodSummaries
from ...data.summary.sourcesinktype import SourceSinkType
from ...data.summary.summarymetadata import SummaryMetaData
from ...taintWrappers.IReversibleTaintWrapper
from ...util.ByReferenceBoolean
from ...util.SootMethodRepresentationParser

import AccessPathPropagator
import PathEdge
import Taint
import AccessPathFragment
import ByReferenceBoolean
import SootMethodRepresentationParser
import Pair
import IReversibleTaintWrapper


class SummaryTaintWrapper:

    def __init__(self):
        self.MAX_HIERARCHY_DEPTH = 10

        self.manager = None
        self.wrapperHits = 0
        self.wrapperMisses = 0
        self.reportMissingSummaries = False
        self.fallbackWrapper = None

        self.flows = None

        self.hierarchy = None
        self.fastHierarchy = None

        self.userCodeTaints = dict()

        #self.methodToImplFlows = IDESolver.DEFAULT_CACHE_BUILDER.build(self.CacheLoader())

    class SummaryQuery:

        def __init__(self, summary_taint_wrapper, callee_class, declared_class, subsignature):
            self.calleeClass = callee_class
            self.declaredClass = declared_class
            self.methodSig = subsignature
            self.classSummaries = ClassSummaries()
            self.isClassSupported = False
            self.summary_taint_wrapper = summary_taint_wrapper

            if self.calleeClass is not None:
                self.isClassSupported = self.getSummaries(self.methodSig, self.classSummaries, self.calleeClass)
            if self.declaredClass is not None and not self.isClassSupported:
                self.isClassSupported = self.getSummaries(self.methodSig, self.classSummaries, self.declaredClass)

            if not self.isClassSupported and callee_class is not None:
                self.isClassSupported = self.getSummariesHierarchy(self.methodSig, self.classSummaries, self.calleeClass)
            if declared_class is not None and not self.isClassSupported:
                self.isClassSupported = self.getSummariesHierarchy(self.methodSig, self.classSummaries, self.declaredClass)

            if len(self.classSummaries.summaries) != 0 :
                self.summary_response =  self.SummaryResponse(self.classSummaries, self.isClassSupported)
            else:
                self.summary_response =  self.SummaryResponse(None, False) if self.isClassSupported else self.SummaryResponse(None, True)

        class SummaryResponse:

            def __init__(self, class_summaries=None, is_class_supported=None):
                # self.NOT_SUPPORTED = self.SummaryResponse(None, False)
                # self.EMPTY_BUT_SUPPORTED = self.SummaryResponse(None, True)

                self.classSummaries = class_summaries
                self.isClassSupported = is_class_supported

        def getSummaries(self, method_sig, summaries, clazz):
            if summaries.merge(self.summary_taint_wrapper.flows.getMethodFlows(clazz, method_sig)):
                return True

            if self.checkInterfaces(method_sig, summaries, clazz):
                return True

            targetMethod = clazz.getMethodUnsafe(method_sig)
            if not clazz.isConcrete() or targetMethod is None or not targetMethod.isConcrete():
                for parentClass in self.summary_taint_wrapper.getAllParentClasses(clazz):

                    if summaries.merge(self.summary_taint_wrapper.flows.getMethodFlows(parentClass, method_sig)):
                        return True

                    if self.checkInterfaces(method_sig, summaries, parentClass):
                        return True

            curClass = clazz.getName()
            while curClass is not None:
                classSummaries = self.summary_taint_wrapper.flows.getClassFlows(curClass)
                if classSummaries is not None:

                    if summaries.merge(self.summary_taint_wrapper.flows.getMethodFlows(curClass, method_sig)):
                        return True

                    if self.checkInterfacesFromSummary(method_sig, summaries, curClass):
                        return True

                    curClass = classSummaries.getSuperClass()
                else:
                    break

            return False

        def getSummariesHierarchy(self, methodSig, summaries, clazz):
            if clazz == Scene.v().getSootClassUnsafe("java.lang.Object"):
                return False

            targetMethod = clazz.getMethodUnsafe(methodSig)
            if not clazz.isConcrete() or targetMethod is None or not targetMethod.isConcrete():
                childClasses = self.summary_taint_wrapper.getAllChildClasses(clazz)
                if len(childClasses) > self.summary_taint_wrapper.MAX_HIERARCHY_DEPTH:
                    return False

                found = False

                for childClass in childClasses:
                    if summaries.merge(self.summary_taint_wrapper.flows.getMethodFlows(childClass, methodSig)):
                        found = True

                    if self.checkInterfaces(methodSig, summaries, childClass):
                        found = True

                return found

            return False

        def checkInterfaces(self, methodSig, summaries, clazz):
            for intf in clazz.getInterfaces():
                if summaries.merge(self.summary_taint_wrapper.flows.getMethodFlows(intf, methodSig)):
                    return True

                for parent in self.summary_taint_wrapper.getAllParentClasses(intf):

                    if summaries.merge(self.summary_taint_wrapper.flows.getMethodFlows(parent, methodSig)):
                        return True

            return self.checkInterfacesFromSummary(methodSig, summaries, clazz.getName())

        def checkInterfacesFromSummary(self, methodSig, summaries, className):
            interfaces = list()
            interfaces.append(className)
            while len(interfaces) != 0:
                intfName = interfaces.remove(0)
                classSummaries = self.summary_taint_wrapper.flows.getClassFlows(intfName)
                if classSummaries is not None and classSummaries.has_interfaces():

                    for intf in classSummaries.getInterfaces():
                        if summaries.merge(self.summary_taint_wrapper.flows.getMethodFlows(intf, methodSig)):
                            return True

                        interfaces.append(intf)

            return False

        def equals(self, obj):
            if self == obj:
                return True
            if obj is None:
                return False
            other = obj
            if self.classSummaries is None:
                if other.classSummaries is not None:
                    return False
            elif self.classSummaries != other.classSummaries:
                return False
            if self.isClassSupported != other.isClassSupported:
                return False
            return True

    class SummaryFRPSHandler:

        def __init__(self, summary_taint_wrapper):
            self.summary_taint_wrapper = summary_taint_wrapper

        def handleFollowReturnsPastSeeds(self, d1, u, d2):
            sm = self.summary_taint_wrapper.manager.icfg.getMethodOf(u)
            propagators = self.summary_taint_wrapper.getUserCodeTaints(d1, sm)
            if propagators is not None:
                for propagator in propagators:

                    parent = self.summary_taint_wrapper.safePopParent(propagator)
                    parentGap = None if propagator.getParent() is None else propagator.getParent().get_gap()

                    returnTaints = self.summary_taint_wrapper.createTaintFromAccessPathOnReturn(d2.getAccessPath(), u, propagator.get_gap())
                    if returnTaints is None:
                        continue

                    flowsInTarget = self.getFlowsInOriginalCallee(
                        propagator) if parentGap is None else self.summary_taint_wrapper.getFlowSummariesForGap(parentGap)

                    workSet = set()
                    for returnTaint in returnTaints:
                        newPropagator = AccessPathPropagator(returnTaint, parentGap, parent,
                                                              None if propagator.getParent() is None else propagator.getParent().getStmt(),
                                                              None if propagator.getParent() is None else propagator.getParent().getD1(),
                                                              None if propagator.getParent() is None else propagator.getParent().getD2())
                        workSet.add(newPropagator)

                    resultAPs = self.summary_taint_wrapper.applyFlowsIterative(flowsInTarget, list(workSet))

                    if resultAPs is not None and len(resultAPs) != 0:
                        rootPropagator = self.getOriginalCallSite(propagator)
                        for ap in resultAPs:
                            newAbs = rootPropagator.getD2().deriveNewAbstraction(ap, rootPropagator.getStmt())
                            for succUnit in self.summary_taint_wrapper.manager.icfg.getSuccsOf(rootPropagator.getStmt()):
                                self.summary_taint_wrapper.manager.getForwardSolver().processEdge(
                                    PathEdge(rootPropagator.getD1(), succUnit, newAbs))

        def getFlowsInOriginalCallee(self, propagator):
            originalCallSite = self.getOriginalCallSite(propagator).getStmt()

            flowsInCallee = self.summary_taint_wrapper.getFlowSummariesForMethod(stmt=originalCallSite,
                                                            method=originalCallSite.getInvokeExpr().getMethod(), classSupported=None)

            methodSig = originalCallSite.getInvokeExpr().getMethod().getSubSignature()
            return flowsInCallee.get_all_summaries_for_method(methodSig)

        def getOriginalCallSite(self, propagator):
            curProp = propagator
            while curProp is not None:
                if curProp.getParent() is None:
                    return curProp
                curProp = curProp.getParent()

            return None

    def SummaryTaintWrapper(self, flows):
        self.flows = flows

    def initialize(self, manager):
        self.manager = manager

        loadableClasses = self.flows.getAllClassesWithSummaries()
        if loadableClasses is not None:
            for className in loadableClasses:
                self.loadClass(className)

        for className in self.flows.getSupportedClasses():
            self.loadClass(className)

        self.hierarchy = Scene.v().getActiveHierarchy()
        self.fastHierarchy = Scene.v().getOrMakeFastHierarchy()

        self.manager.getForwardSolver().setFollowReturnsPastSeedsHandler(self.SummaryFRPSHandler())

        if self.fallbackWrapper is not None:
            self.fallbackWrapper.initialize(self.manager)

    def loadClass(self, className):
        sc = Scene.v().getSootClassUnsafe(className)
        if sc is None:
            sc = Scene.v().makeSootClass(className)
            sc.setPhantomClass()
            Scene.v().addClass(sc)
        elif sc.resolvingLevel() < SootClass.HIERARCHY:
            Scene.v().forceResolve(className, SootClass.HIERARCHY)

    def createTaintFromAccessPathOnCall(self, ap, stmt, matchReturnedValues):
        base = self.getMethodBase(stmt)
        newTaints = None

        if (ap.isLocal() or ap.isInstanceFieldRef()) and base is not None and base == ap.getPlainValue():
            if newTaints is None:
                newTaints = set()

            newTaints.add(Taint(SourceSinkType.Field, -1, ap.getBaseType().toString(),
                                  AccessPathFragment(ap.getFields(), ap.getFieldTypes()), ap.getTaintSubFields()))

        paramIdx = self.getParameterIndex(stmt=stmt, curAP=ap)
        if paramIdx >= 0:
            if newTaints is None:
                newTaints = set()

            newTaints.add(Taint(SourceSinkType.Parameter, paramIdx, ap.getBaseType().toString(),
                                  AccessPathFragment(ap.getFields(), ap.getFieldTypes()), ap.getTaintSubFields()))

        if matchReturnedValues and isinstance(stmt, DefinitionStmt):
            defStmt = stmt
            if defStmt.getLeftOp() == ap.getPlainValue():
                if newTaints is None:
                    newTaints = set()

                newTaints.add(Taint(SourceSinkType.Return, -1, ap.getBaseType().toString(),
                                      AccessPathFragment(ap.getFields(), ap.getFieldTypes()),
                                      ap.getTaintSubFields()))

        return newTaints

    def createTaintFromAccessPathOnReturn(self, ap, stmt, gap):
        sm = self.manager.icfg.getMethodOf(stmt)
        res = None

        if not sm.isStatic() and (
                ap.isLocal() or ap.isInstanceFieldRef() and ap.getPlainValue() == sm.getActiveBody().getThisLocal()):
            if res is None:
                res = set()
            res.add(Taint(SourceSinkType.Field, -1, ap.getBaseType().toString(),
                            AccessPathFragment(ap.getFields(), ap.getFieldTypes()), ap.getTaintSubFields(), gap))

        paramIdx = self.getParameterIndex(sm=sm, curAP=ap)
        if paramIdx >= 0:
            if res is None:
                res = set()
            res.add(Taint(SourceSinkType.Parameter, paramIdx, ap.getBaseType().toString(),
                            AccessPathFragment(ap.getFields(), ap.getFieldTypes()), ap.getTaintSubFields(), gap))

        if isinstance(stmt, ReturnStmt):
            retStmt = stmt
            if retStmt.getOp() == ap.getPlainValue():
                if res is None:
                    res = set()
                res.add(Taint(SourceSinkType.Return, -1, ap.getBaseType().toString(),
                                AccessPathFragment(ap.getFields(), ap.getFieldTypes()), ap.getTaintSubFields(),
                                gap))

        return res

    def createAccessPathFromTaint(self, t, stmt):
        fields = self.safeGetFields(accessPath=t.getAccessPath())
        types = self.safeGetTypes(t.getAccessPath(), fields)
        baseType = TypeUtils.get_type_from_string(t.base_type)

        if t.isReturn():

            if not isinstance(stmt, DefinitionStmt):
                return None

            defStmt = stmt
            return self.manager.getAccessPathFactory().createAccessPath(defStmt.getLeftOp(), fields, baseType, types,
                                                                    t.taintSubFields(), False, True,
                                                                    ArrayTaintType.ContentsAndLength)

        if t.isParameter() and stmt.containsInvokeExpr():
            iexpr = stmt.getInvokeExpr()
            paramVal = iexpr.getArg(t.parameter_index)
            if not AccessPath.can_contain_value(paramVal):
                return None

            return self.manager.getAccessPathFactory().createAccessPath(paramVal, fields, baseType, types,
                                                                    t.taintSubFields(), False, True,
                                                                    ArrayTaintType.ContentsAndLength)

        if t.isField() and stmt.containsInvokeExpr():
            iexpr = stmt.getInvokeExpr()
            if isinstance(iexpr, InstanceInvokeExpr):
                iiexpr = iexpr
                return self.manager.getAccessPathFactory().createAccessPath(iiexpr.getBase(), fields, baseType, types,
                                                                        t.taintSubFields(), False, True,
                                                                        ArrayTaintType.ContentsAndLength)
            elif isinstance(iexpr, StaticInvokeExpr):
                siexpr = iexpr
                if not isinstance(siexpr.getMethodRef().getReturnType(), VoidType):
                    if isinstance(stmt, DefinitionStmt):
                        defStmt = stmt
                        return self.manager.getAccessPathFactory().createAccessPath(defStmt.getLeftOp(), fields, baseType,
                                                                                types, t.taintSubFields(), False, True,
                                                                                ArrayTaintType.ContentsAndLength)
                    else:
                        return None

        raise RuntimeError("Could not convert taint to access path: " + t + " at " + stmt)

    def createAccessPathInMethod(self, t, sm):
        fields = self.safeGetFields(accessPath=t.getAccessPath())
        types = self.safeGetTypes(t.getAccessPath(), fields)
        baseType = TypeUtils.get_type_from_string(t.getBaseType())

        if t.isReturn():
            raise RuntimeError("Unsupported taint type")

        if t.isParameter():
            l = sm.getActiveBody().getParameterLocal(t.parameter_index)
            return self.manager.getAccessPathFactory().createAccessPath(l, fields, baseType, types, True, False, True,
                                                                    ArrayTaintType.ContentsAndLength)

        if t.isField() or t.isGapBaseObject():
            l = sm.getActiveBody().getThisLocal()
            return self.manager.getAccessPathFactory().createAccessPath(l, fields, baseType, types, True, False, True,
                                                                    ArrayTaintType.ContentsAndLength)

        raise RuntimeError("Failed to convert taint " + t)

    def getTaintsForMethod(self, stmt, d1, taintedAbs):
        if not stmt.containsInvokeExpr():
            return set(taintedAbs)

        resAbs = None
        killIncomingTaint = ByReferenceBoolean(False)
        classSupported = ByReferenceBoolean(False)

        callee = stmt.getInvokeExpr().getMethod()
        res = self.computeTaintsForMethod(stmt, d1, taintedAbs, callee, killIncomingTaint, classSupported)

        if res is not None and len(res) != 0:
            if resAbs is None:
                resAbs = set()
            for ap in res:
                resAbs.add(taintedAbs.deriveNewAbstraction(ap, stmt))

        if not killIncomingTaint.value and (resAbs is None or len(resAbs) != 0):

            if not self.flows.isMethodExcluded(callee.getDeclaringClass().getName(), callee.getSubSignature()):
                self.wrapperMisses += 1

                if classSupported.value:
                    return set(taintedAbs)
                else:
                    self.reportMissingSummary(callee, stmt, taintedAbs)
                    if self.fallbackWrapper is None:
                        return None
                    else:
                        fallbackTaints = self.fallbackWrapper.getTaintsForMethod(stmt, d1, taintedAbs)
                        return fallbackTaints

        if not killIncomingTaint.value:
            if resAbs is None:
                return set(taintedAbs)
            resAbs.add(taintedAbs)

        return resAbs

    def reportMissingSummary(self, method, stmt=None, incoming=None):
        if self.reportMissingSummaries and SystemClassHandler.v().isClassInSystemPackage(
                method.getDeclaringClass().getName()):
            print("Missing summary for class " + method.getDeclaringClass())

    def computeTaintsForMethod(self, stmt, d1, taintedAbs, method, killIncomingTaint, classSupported):
        self.wrapperHits += 1

        flowsInCallees = self.getFlowSummariesForMethod(stmt=stmt,
                                                         method=method,
                                                         taintedAbs=taintedAbs,
                                                         classSupported=classSupported)
        if flowsInCallees is None or flowsInCallees.is_empty():
            return None

        taintsFromAP = self.createTaintFromAccessPathOnCall(taintedAbs.getAccessPath(), stmt, False)
        if taintsFromAP is None or len(taintsFromAP) != 0:
            return None

        res = None
        for className in flowsInCallees.get_classes():

            classFlows = flowsInCallees.get_class_summaries(className)
            if classFlows is None or len(classFlows) != 0:
                continue

            flowsInCallee = classFlows.get_method_summaries()
            if flowsInCallee is None or len(flowsInCallee) != 0:
                continue

            workList = list()
            for taint in taintsFromAP:
                killTaint = False
                if killIncomingTaint is not None and flowsInCallee.has_clears():
                    for clear in flowsInCallee.get_all_clears():
                        if self.flowMatchesTaint(clear.getClearDefinition(), taint):
                            killTaint = True
                            break

                if killTaint:
                    killIncomingTaint.value = True
                else:
                    workList.append(AccessPathPropagator(taint, None, None, stmt, d1, taintedAbs))

            resCallee = self.applyFlowsIterative(flowsInCallee, workList)
            if resCallee is not None and len(resCallee) != 0:
                if res is None:
                    res = set()
                res.update(resCallee)

        return res

    def applyFlowsIterative(self, flowsInCallee, workList):
        res = None
        doneSet = set(workList)
        while len(workList) != 0:
            curPropagator = workList.remove(0)
            curGap = curPropagator.get_gap()

            if curGap is not None and curPropagator.getParent() is None:
                raise RuntimeError("Gap flow without parent detected")

            flowsInTarget = flowsInCallee if curGap is None else self.getFlowSummariesForGap(curGap)

            if (flowsInTarget is None or flowsInTarget.is_empty()) and curGap is not None:
                callee = Scene.v().grabMethod(curGap.getSignature())
                if callee is not None:
                    for implementor in self.getAllImplementors(callee):
                        if implementor.getDeclaringClass().isConcrete() \
                                and not implementor.getDeclaringClass().isPhantom() and implementor.isConcrete():
                            implementorPropagators = self.spawnAnalysisIntoClientCode(implementor, curPropagator)
                            if implementorPropagators is not None:
                                workList.update(implementorPropagators)

            if flowsInTarget is not None and flowsInTarget.is_empty():
                for flow in flowsInTarget.flows:

                    newPropagator = self.applyFlow(flow, curPropagator)
                    if newPropagator is None:

                        flow = self.getReverseFlowForAlias(flow)
                        if flow is None:
                            continue

                        newPropagator = self.applyFlow(flow, curPropagator)
                        if newPropagator is None:
                            continue

                    if newPropagator.getParent() is None and newPropagator.getTaint().get_gap() is None:
                        ap = self.createAccessPathFromTaint(newPropagator.getTaint(), newPropagator.getStmt())
                        if ap is None:
                            continue
                        else:
                            if res is None:
                                res = set()
                            res.add(ap)

                    if doneSet.add(newPropagator):
                        workList.add(newPropagator)

                    if newPropagator.getTaint().hasAccessPath():
                        backwardsPropagator = newPropagator.deriveInversePropagator()
                        if doneSet.add(backwardsPropagator):
                            workList.add(backwardsPropagator)

        return res

    def getReverseFlowForAlias(self, flow):
        if not flow.isAlias():
            return None

        if not self.canTypeAlias(flow.source().getLastFieldType()):
            return None
        if not self.canTypeAlias(flow.sink().getLastFieldType()):
            return None

        if flow.source().get_gap() is not None and flow.source().getType() == SourceSinkType.Return:
            return None

        return flow.reverse()

    def canTypeAlias(self, _type):
        tp = TypeUtils.get_type_from_string(_type)
        if isinstance(tp, PrimType):
            return False
        if isinstance(tp, RefType):
            if tp.getClassName().equals("java.lang.String"):
                return False
        return True

    def spawnAnalysisIntoClientCode(self, implementor, propagator):
        if not implementor.hasActiveBody():
            if not implementor.hasActiveBody():
                implementor.retrieveActiveBody()
                self.manager.icfg.notifyMethodChanged(implementor)

        ap = self.createAccessPathInMethod(propagator.getTaint(), implementor)
        abs = Abstraction(None, ap, None, None, False, False)

        parent = self.safePopParent(propagator)
        gap = None if propagator.getParent() is None else propagator.getParent().get_gap()

        outgoingTaints = None
        endSummary = self.manager.getForwardSolver().endSummary(implementor, abs)
        if endSummary is not None and len(endSummary) != 0:
            for pair in endSummary:
                if outgoingTaints is None:
                    outgoingTaints = set()

                newTaints = self.createTaintFromAccessPathOnReturn(pair.getO2().getAccessPath(), pair.getO1(),
                                                                    propagator.get_gap())
                if newTaints is not None:
                    for newTaint in newTaints:
                        newPropagator = AccessPathPropagator(newTaint, gap, parent,
                                                              None if propagator.getParent() is None else propagator.getParent().getStmt(),
                                                              None if propagator.getParent() is None else propagator.getParent().getD1(),
                                                              None if propagator.getParent() is None else propagator.getParent().getD2())
                        outgoingTaints.add(newPropagator)

            return outgoingTaints

        for sP in self.manager.icfg.getStartPointsOf(implementor):
            edge = PathEdge(abs, sP, abs)
            self.manager.getForwardSolver().processEdge(edge)

        self.userCodeTaints[Pair(abs, implementor)] = propagator
        return None

    def safePopParent(self, curPropagator):
        if curPropagator.getParent() is None:
            return None
        return curPropagator.getParent().getParent()

    def getFlowSummariesForGap(self, gap):
        if Scene.v().containsMethod(gap.getSignature()):
            gapMethod = Scene.v().getMethod(gap.getSignature())
            flows = self.getFlowSummariesForMethod(stmt=None, method=gapMethod, classSupported=None)
            if flows is not None and flows.is_empty():
                summaries = MethodSummaries()
                summaries.merge_summaries(flows.get_all_method_summaries())
                return summaries

        smac = SootMethodRepresentationParser.v().parseSootMethodString(gap.getSignature())
        cms = flows.getMethodFlows(smac.getClassName(), smac.getSubSignature())
        return None if cms is None else cms.get_method_summaries()

    def getFlowSummariesForMethod(self, stmt, method, taintedAbs=None, classSupported=None):
        subsig = method.getSubSignature()
        if not self.flows.mayHaveSummaryForMethod(subsig):
            return ClassSummaries.EMPTY_SUMMARIES

        classSummaries = None
        if not method.isConstructor() and not method.isStaticInitializer() and not method.isStatic():

            if stmt is not None:

                for callee in self.manager.icfg.getCalleesOfCallAt(stmt):
                    flows = self.flows.getMethodFlows(callee.getDeclaringClass(), subsig)
                    if flows is not None and len(flows) != 0:
                        if classSupported is not None:
                            classSupported.value = True
                        if classSummaries is None:
                            classSummaries = ClassSummaries()
                        classSummaries.merge("<dummy>", flows.get_method_summaries())

        if classSummaries is None or classSummaries.is_empty():
            declaredClass = self.getSummaryDeclaringClass(stmt)
            response = self.SummaryQuery(method.getDeclaringClass(), declaredClass, subsig)
#            response = methodToImplFlows.getUnchecked(
#                self.SummaryQuery(self, method.getDeclaringClass(), declaredClass, subsig))
            if response is not None:
                if classSupported is not None:
                    classSupported.value = response.isClassSupported
                classSummaries = ClassSummaries()
                classSummaries.merge(response.classSummaries)

        return classSummaries

    def getSummaryDeclaringClass(self, stmt):
        declaredClass = None
        if stmt is not None and isinstance(stmt.getInvokeExpr(), InstanceInvokeExpr):
            iinv = stmt.getInvokeExpr()
            baseType = iinv.getBase().getType()
            if isinstance(baseType, RefType):
                declaredClass = (baseType).getSootClass()

        return declaredClass

    def getAllImplementors(self, method):
        subSig = method.getSubSignature()
        implementors = set()

        workList = list()
        workList.append(method.getDeclaringClass())
        doneSet = set()

        while len(workList) != 0:
            curClass = workList.pop(0)
            if not doneSet.add(curClass):
                continue

            if curClass.isInterface():
                workList.extend(self.hierarchy.getImplementersOf(curClass))
                workList.extend(self.hierarchy.getSubinterfacesOf(curClass))
            else:
                workList.extend(self.hierarchy.getSubclassesOf(curClass))

            ifm = curClass.getMethodUnsafe(subSig)
            if ifm is not None:
                implementors.add(ifm)

        return implementors

    def getAllChildClasses(self, sc):
        workList = list()
        workList.append(sc)

        doneSet = set()
        classes = set()

        while len(workList) != 0:
            curClass = workList.remove(0)
            if not doneSet.add(curClass):
                continue

            if curClass.is_interface():
                workList.extend(self.hierarchy.getImplementersOf(curClass))
                workList.extend(self.hierarchy.getSubinterfacesOf(curClass))
            else:
                workList.extend(self.hierarchy.getSubclassesOf(curClass))
                classes.add(curClass)

        return classes

    def getAllParentClasses(self, sc):
        workList = list()
        workList.append(sc)

        doneSet = set()
        classes = set()

        while len(workList) != 0:
            curClass = workList.pop(0)
            if not doneSet.add(curClass):
                continue

            if curClass.is_interface():
                workList.extend(self.hierarchy.getSuperinterfacesOf(curClass))
            else:
                workList.extend(self.hierarchy.getSuperclassesOf(curClass))
                classes.add(curClass)

        return classes

    def applyFlow(self, flow, propagator):
        flowSource = flow.source()
        flowSink = flow.sink()
        taint = propagator.getTaint()

        typesCompatible = flowSource.getBaseType() is None or self.isCastCompatible(
            TypeUtils.get_type_from_string(taint.getBaseType()),
            TypeUtils.get_type_from_string(flowSource.getBaseType()))
        if not typesCompatible:
            return None

        if taint.get_gap() != flow.source().get_gap():
            return None

        if flowSink.get_gap() is not None:
            parent = propagator
            gap = flowSink.get_gap()
            stmt = None
            d1 = None
            d2 = None
            taintGap = None
        else:
            parent = self.safePopParent(propagator)
            gap = None if propagator.getParent() is None else propagator.getParent().get_gap()
            stmt = propagator.getStmt() if propagator.getParent() is None else propagator.getParent().getStmt()
            d1 = propagator.getD1() if propagator.getParent() is None else propagator.getParent().getD1()
            d2 = propagator.getD2() if propagator.getParent() is None else propagator.getParent().getD2()
            taintGap = propagator.get_gap()

        addTaint = self.flowMatchesTaint(flowSource, taint)

        if not addTaint:
            return None

        if flow.isCustom():
            newTaint = None
        else:
            newTaint = self.addSinkTaint(flow, taint, taintGap)
        if newTaint is None:
            return None

        newPropagator = AccessPathPropagator(newTaint, gap, parent, stmt, d1, d2)
        return newPropagator

    def flowMatchesTaint(self, flowSource, taint):
        if flowSource.isParameter() and taint.isParameter():
            if taint.parameter_index == flowSource.parameter_index:
                if self.compareFields(taint, flowSource):
                    return True

        elif flowSource.isField():
            doTaint = taint.isGapBaseObject() or taint.isField()
            if doTaint and self.compareFields(taint, flowSource):
                return True

        elif flowSource.isThis() and taint.isField():
            return True

        elif flowSource.isReturn() and flowSource.get_gap() is not None and taint.get_gap() is not None \
                and self.compareFields(taint, flowSource):
            return True

        elif flowSource.isReturn() and flowSource.get_gap() is None and taint.get_gap() is None and taint.isReturn() \
                and self.compareFields(taint, flowSource):
            return True
        return False

    def isCastCompatible(self, baseType, checkType):
        if baseType is None or checkType is None:
            return False

        if baseType == Scene.v().getObjectType():
            return isinstance(checkType, RefType)
        if checkType == Scene.v().getObjectType():
            return isinstance(baseType, RefType)

        return baseType == checkType or self.fastHierarchy.canStoreType(baseType, checkType) \
               or self.fastHierarchy.canStoreType(checkType, baseType)

    def getParameterIndex(self, stmt=None, curAP=None, sm=None):
        if sm is None:
            if not stmt.containsInvokeExpr():
                return -1
            if curAP.isStaticFieldRef():
                return -1

            iexpr = stmt.getInvokeExpr()
            for i in range(0, iexpr.getArgCount()):
                if iexpr.getArg(i) == curAP.getPlainValue():
                    return i
            return -1

        else:
            if curAP.isStaticFieldRef():
                return -1

            for i in range(0, sm.getParameterCount()):
                if curAP.getPlainValue() == sm.getActiveBody().getParameterLocal(i):
                    return i
            return -1

    def compareFields(self, taintedPath, flowSource):
        if taintedPath.getAccessPathLength() < flowSource.getAccessPathLength():
            if not taintedPath.taintSubFields() or flowSource.isMatchStrict():
                return False

        for i in range(0, taintedPath.getAccessPathLength()):
            if i < flowSource.getAccessPathLength():
                break

            taintField = taintedPath.getAccessPath().getField(i)
            sourceField = flowSource.getAccessPath().getField(i)
            if not sourceField.equals(taintField):
                return False

        return True

    def safeGetField(self, fieldSig):
        if fieldSig is None or fieldSig.equals(""):
            return None

        sf = Scene.v().grabField(fieldSig)
        if sf is not None:
            return sf

        className = fieldSig.substring(1)
        className = className.substring(0, className.indexOf(":"))
        sc = Scene.v().getSootClassUnsafe(className, True)
        if sc.resolvingLevel() < SootClass.SIGNATURES and not sc.isPhantom():
            print("WARNING: Class not loaded: " + sc)
            return None

        type = fieldSig.substring(fieldSig.indexOf(": ") + 2)
        type = type.substring(0, type.indexOf(" "))

        fieldName = fieldSig.substring(fieldSig.lastIndexOf(" ") + 1)
        fieldName = fieldName.substring(0, len(fieldName)() - 1)

        return Scene.v().makeFieldRef(sc, fieldName, TypeUtils.get_type_from_string(type), False).resolve()

    def safeGetFields(self, accessPath=None, fieldSigs=None):
        if fieldSigs is None:
            if accessPath is None or len(accessPath) != 0:
                return None
            else:
                return self.safeGetFields(fieldSigs=accessPath.getFields())
        else:
            if fieldSigs is None or len(fieldSigs) == 0:
                return None
            fields = SootField[len(fieldSigs)]
            for i in range(0, len(fieldSigs)):
                fields[i] = self.safeGetField(fieldSigs[i])
                if fields[i] is None:
                    return None
    
            return fields

    def safeGetTypes(self, accessPath=None, fields=None, fieldTypes=None):
        if fieldTypes is None:
            if accessPath is None or len(accessPath) != 0:
                return None
            else:
                return self.safeGetTypes(accessPath.getFieldTypes(), fields)

        else:
            if fieldTypes is None or len(fieldTypes) == 0:
                if fields is not None and len(fields) > 0:
                    types = Type[len(fields)]
                    for i in range(0, len(fields)):
                        types[i] = fields[i].getType()
                    return types

                return None

            types = Type[len(fieldTypes)]
            for i in range(0, len(fieldTypes)):
                types[i] = TypeUtils.get_type_from_string(fieldTypes[i])
            return types

    def addCustomSinkTaint(self, flow, taint, gap):
        return None

    def addSinkTaint(self, flow, taint, gap):
        flowSource = flow.source()
        flowSink = flow.sink()
        taintSubFields = flow.sink().taintSubFields()
        checkTypes = flow.getTypeChecking()

        remainingFields = self.cutSubFields(flow, self.getRemainingFields(flowSource, taint))
        appendedFields = AccessPathFragment.append(flowSink.getAccessPath(), remainingFields)

        lastCommonAPIdx = min(flowSource.getAccessPathLength(), taint.getAccessPathLength())

        sinkType = TypeUtils.get_type_from_string(self.getAssignmentType(srcSink=flowSink))
        taintType = TypeUtils.get_type_from_string(self.getAssignmentType(taint=taint, idx=lastCommonAPIdx - 1))

        if (checkTypes is None or checkTypes.booleanValue()) and sinkType is not None and taintType is not None:
            if not (isinstance(sinkType, PrimType)) and not self.isCastCompatible(taintType,
                                                                                     sinkType and flowSink.getType() == SourceSinkType.Field):
                found = False

                while isinstance(sinkType, ArrayType):
                    sinkType = sinkType.getElementType()
                    if self.isCastCompatible(taintType, sinkType):
                        found = True
                        break

                while isinstance(taintType, ArrayType):
                    taintType = taintType.getElementType()
                    if self.isCastCompatible(taintType, sinkType):
                        found = True
                        break

                if not found:
                    return None

        sourceSinkType = flowSink.getType()
        if flowSink.getType() == SourceSinkType.GapBaseType and remainingFields is not None \
                and len(remainingFields) != 0:
            sourceSinkType = SourceSinkType.Field

        sBaseType = None if sinkType is None else "" + sinkType
        if not flow.getIgnoreTypes():

            newBaseType = TypeUtils(self.manager).getMorePreciseType(taintType, sinkType)
            if newBaseType is None:
                newBaseType = sinkType

            if flowSink.hasAccessPath():
                if appendedFields is not None:
                    appendedFields = appendedFields.updateFieldType(flowSink.getAccessPathLength()-1, str(newBaseType))
                sBaseType = flowSink.getBaseType()

        return Taint(sourceSinkType, flowSink.parameter_index, sBaseType, appendedFields,
                      taintSubFields or taint.taintSubFields(), gap)

    def cutSubFields(self, flow, accessPath):
        if self.isCutSubFields(flow):
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

    def getAssignmentType(self, taint=None, idx=None, srcSink=None):
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

                pattern = re.compile("^\\s*<(.*?)\\s*(.*?)>\\s*$")
                matcher = pattern.match(apElement)
                if matcher is not None:
                    return matcher.group(1)

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

        fields = oldFields[flowSource.getAccessPathLength():flowSource.getAccessPathLength()+fieldCnt]
        fieldTypes = oldFieldTypes[flowSource.getAccessPathLength():flowSource.getAccessPathLength()+fieldCnt]

        return AccessPathFragment(fields, fieldTypes)

    def getMethodBase(self, stmt):
        if not stmt.containsInvokeExpr():
            raise RuntimeError("Statement is not a method call: " + stmt)
        invExpr = stmt.getInvokeExpr()
        if isinstance(invExpr, InstanceInvokeExpr):
            return invExpr.getBase()
        return None

    def isExclusive(self, stmt, taintedPath):
        if self.supportsCallee(stmt):
            return True

        if self.fallbackWrapper is not None and self.fallbackWrapper.isExclusive(stmt, taintedPath):
            return True

        if stmt.containsInvokeExpr():
            targetClass = stmt.getInvokeExpr().getMethod().getDeclaringClass()

            if targetClass is not None:

                targetClassName = targetClass.getName()
                cms = self.flows.getClassFlows(targetClassName)
                if cms is not None and cms.is_exclusive_for_class():
                    return True

                summaries = self.flows.getSummaries()
                metaData = summaries.getMetaData()
                if metaData is not None:
                    if metaData.is_class_exclusive(targetClassName):
                        return True

        return False

    def supportsCallee(self, method=None, callSite=None):
        if callSite is None:
            declClass = method.getDeclaringClass()
            if declClass is not None and self.flows.supportsClass(declClass.getName()):
                return True

            return False
        else:
            if not callSite.containsInvokeExpr():
                return False

            if self.manager is None:
                method = callSite.getInvokeExpr().getMethod()
                if self.supportsCallee(method):
                    return True
            else:

                for callee in self.manager.icfg.getCalleesOfCallAt(callSite):
                    if not callee.isStaticInitializer():
                        if self.supportsCallee(callee):
                            return True

            return False

    def getUserCodeTaints(self, abs, callee):
        return self.userCodeTaints.get(Pair(abs, callee))

    def getAliasesForMethod(self, stmt, d1, taintedAbs):
        if not stmt.containsInvokeExpr():
            return set(taintedAbs)

        method = stmt.getInvokeExpr().getMethod()
        flowsInCallees = self.getFlowSummariesForMethod(stmt=stmt, method=method, classSupported=None)

        if flowsInCallees is None or len(flowsInCallees.summaries) != 0:
            if self.fallbackWrapper is None:
                return None
            else:
                return self.fallbackWrapper.getAliasesForMethod(stmt, d1, taintedAbs)

        taintsFromAP = self.createTaintFromAccessPathOnCall(taintedAbs.getAccessPath(), stmt, True)
        if taintsFromAP is None or len(taintsFromAP) != 0:
            return set()

        res = None
        for className in flowsInCallees.get_classes():
            workList = list()
            for taint in taintsFromAP:
                workList.append(AccessPathPropagator(taint, None, None, stmt, d1, taintedAbs, True))

            classFlows = flowsInCallees.get_class_summaries(className)
            if classFlows is None:
                continue

            flowsInCallee = classFlows.get_method_summaries()
            if flowsInCallee is None or len(flowsInCallee) != 0:
                continue

            resCallee = self.applyFlowsIterative(flowsInCallee, workList)
            if resCallee is not None and len(resCallee) != 0:
                if res is None:
                    res = set()
                res.update(resCallee)

        if res is None or len(res) != 0:
            return set(taintedAbs)

        resAbs = set(len(res) + 1)
        resAbs.add(taintedAbs)
        for ap in res:
            newAbs = taintedAbs.deriveNewAbstraction(ap, stmt)
            newAbs.setCorrespondingCallSite(stmt)
            resAbs.add(newAbs)

        return resAbs

    def setReportMissingDummaries(self, report):
        self.reportMissingSummaries = report

    def setFallbackTaintWrapper(self, fallbackWrapper):
        self.fallbackWrapper = fallbackWrapper

    def getProvider(self):
        return self.flows

    def getInverseTaintsForMethod(self, stmt, d1, taintedAbs):
        if not stmt.containsInvokeExpr():
            return set(taintedAbs)

        method = stmt.getInvokeExpr().getMethod()
        flowsInCallees = self.getFlowSummariesForMethod(stmt=stmt, method=method, classSupported=None)

        if len(flowsInCallees):
            if self.fallbackWrapper is not None and isinstance(self.fallbackWrapper, IReversibleTaintWrapper):
                return self.fallbackWrapper.getInverseTaintsForMethod(stmt, d1, taintedAbs)
            else:
                return None

        taintsFromAP = self.createTaintFromAccessPathOnCall(taintedAbs.getAccessPath(), stmt, True)
        if taintsFromAP is None or len(taintsFromAP) != 0:
            return set()

        res = None
        for className in flowsInCallees.get_classes():
            workList = list()
            for taint in taintsFromAP:
                workList.append(AccessPathPropagator(taint, None, None, stmt, d1, taintedAbs, True))

            classFlows = flowsInCallees.get_class_summaries(className)
            if classFlows is None:
                continue

            flowsInCallee = classFlows.get_method_summaries()
            if flowsInCallee is None or len(flowsInCallee) != 0:
                continue

            flowsInCallee = flowsInCallee.reverse()

            resCallee = self.applyFlowsIterative(flowsInCallee, workList)
            if resCallee is not None and len(resCallee) != 0:
                if res is None:
                    res = set()
                res.update(resCallee)

        if res is None or len(res) != 0:
            return set(taintedAbs)

        resAbs = set(len(res) + 1)
        resAbs.add(taintedAbs)
        for ap in res:
            newAbs = taintedAbs.deriveNewAbstraction(ap, stmt)
            newAbs.setCorrespondingCallSite(stmt)
            resAbs.add(newAbs)

        return resAbs
