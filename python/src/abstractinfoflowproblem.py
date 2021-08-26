import logging
import DefaultJimpleIFDSTabulationProblem
import HashSet, HashMap, MyConcurrentHashMap
import ConcurrentHashSet
import DefinitionStmt
import CaughtExceptionRef
import FlowDroidEssentialMethodTag
import Abstraction
import SystemClassHandler

logger = logging.getLogger(__file__)


class AbstractInfoflowProblem(DefaultJimpleIFDSTabulationProblem):
    
    def __init__(self, manager):
        self.manager = manager
        self.initialSeeds = HashMap()
        self.taintWrapper = None
        self.ncHandler = None
        self.zeroValue = None
        self.solver = None
        self.taintPropagationHandler = None
        self.activationUnitsToCallSites = MyConcurrentHashMap()
        super(manager.getICFG())

    def setSolver(self, solver):
        self.solver = solver

    def setZeroValue(self, zeroValue):
        self.zeroValue = zeroValue

    def followReturnsPastSeeds(self):
        return True

    def setTaintWrapper(self, wrapper):
        self.taintWrapper = wrapper

    def setNativeCallHandler(self, handler):
        self.ncHandler = handler

    def isInitialMethod(self, sm):
        for u in self.initialSeeds.keySet():
            if (self.interproceduralCFG().getMethodOf(u) == sm):
                return True
        return False

    def initialSeeds(self):
        return self.initialSeeds

    def autoAddZero(self):
        return False

    def isCallSiteActivatingTaint(self, callSite, activationUnit):
        if not self.manager.getConfig().getFlowSensitiveAliasing():
            return False

        if activationUnit == None:
            return False
        callSites = self.activationUnitsToCallSites.get(activationUnit)
        return callSites is not None and callSites.contains(callSite)

    def registerActivationCallSite(self, callSite, callee, activationAbs):
        if not self.manager.getConfig().getFlowSensitiveAliasing():
            return False
        activationUnit = activationAbs.getActivationUnit()
        if activationUnit == None:
            return False

        callSites = self.activationUnitsToCallSites.putIfAbsentElseGet(activationUnit, ConcurrentHashSet())
        if callSites.contains(callSite):
            return False

        if not activationAbs.isAbstractionActive():
            if not callee.getActiveBody().getUnits().contains(activationUnit):
                found = False
                for au in callSites:
                    if callee.getActiveBody().getUnits().contains(au):
                        found = True
                        break
                if not found:
                    return False

        return callSites.add(callSite)

    def setActivationUnitsToCallSites(self, other):
        self.activationUnitsToCallSites = other.activationUnitsToCallSites

    def interproceduralCFG(self):
        return super.interproceduralCFG()

    def addInitialSeeds(self, unit, seeds):
        if self.initialSeeds.containsKey(unit):
            self.initialSeeds.get(unit).addAll(seeds)
        else:
            self.initialSeeds.put(unit, HashSet(seeds))

    def hasInitialSeeds(self):
        return not self.initialSeeds.isEmpty()

    def getInitialSeeds(self):
        return self.initialSeeds

    def setTaintPropagationHandler(self, handler):
        self.taintPropagationHandler = handler

    def createZeroValue(self):
        if self.zeroValue is None:
            self.zeroValue = Abstraction.getZeroAbstraction(self.manager.getConfig().getFlowSensitiveAliasing())
        return self.zeroValue

    def getZeroValue(self):
        return self.zeroValue

    def isExceptionHandler(self, u):
        if isinstance(u, DefinitionStmt):
            self.defStmt = u
            return isinstance(self.defStmt.getRightOp(), CaughtExceptionRef)
        return False

    def notifyOutFlowHandlers(self, stmt, d1, incoming, outgoing, functionType):
        if self.taintPropagationHandler is not None and outgoing is not None and not outgoing.isEmpty():
            outgoing = self.taintPropagationHandler.notifyFlowOut(stmt, d1, incoming, outgoing, self.manager, functionType)
        return outgoing

    def computeValues(self):
        return False

    def getManager(self):
        return self.manager

    def isExcluded(self, sm):
        if sm.hasTag(FlowDroidEssentialMethodTag.TAG_NAME):
            return False

        if self.manager.getConfig().getExcludeSootLibraryClasses():
            self.declClass = sm.getDeclaringClass()
            if self.declClass is not None and self.declClass.isLibraryClass():
                return True

        if self.manager.getConfig().getIgnoreFlowsInSystemPackages():
            self.declClass = sm.getDeclaringClass()
            if self.declClass is not None and SystemClassHandler.v().isClassInSystemPackage(self.declClass.getName()):
                return True

        return False
