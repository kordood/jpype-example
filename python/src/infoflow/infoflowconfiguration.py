import logging
from .misc.pyenum import PyEnum

logger = Logging.getLogger(__file__)


SootIntegrationMode = PyEnum('CreateNewInstance', 'UseExistingInstance', 'UseExistingCallgraph')
CallgraphAlgorithm = PyEnum('AutomaticSelection', 'CHA', 'VTA', 'RTA', 'SPARK', 'GEOM', 'OnDemand')
AliasingAlgorithm = PyEnum('FlowSensitive', 'PtsBased', '_None', 'Lazy')
CodeEliminationMode = PyEnum('NoCodeElimination', 'PropagateConstants', 'RemoveSideEffectFreeCode')
DataFlowSolver = PyEnum('ContextFlowSensitive', 'FlowInsensitive', 'GarbageCollecting')
ImplicitFlowMode = PyEnum('NoImplicitFlows', 'ArrayAccesses', 'AllImplicitFlows')
PathReconstructionMode = PyEnum('NoPaths', 'Fast', 'Precise')
PathBuildingAlgorithm = PyEnum('Recursive', 'ContextSensitive', 'ContextInsensitive', 'ContextInsensitiveSourceFinder',
                               '_None')
StaticFieldTrackingMode = PyEnum('ContextFlowSensitive', 'ContextFlowInsensitive', '_None')
SourceSinkFilterMode = PyEnum('UseAllButExcluded', 'UseOnlyIncluded')
CategoryMode = PyEnum('Include', 'Exclude')
CallbackSourceMode = PyEnum('NoParametersAsSources', 'AllParametersAsSources', 'SourceListOnly')
LayoutMatchingMode = PyEnum('NoMatch', 'MatchAll', 'MatchSensitiveOnly')


class SourceSinkConfiguration:

    def __init__(self):
        self.callbackSourceMode = CallbackSourceMode.SourceListOnly
        self.enableLifecycleSources = False
        self.layoutMatchingMode = LayoutMatchingMode.MatchSensitiveOnly
        self.sourceFilterMode = SourceSinkFilterMode.UseAllButExcluded
        self.sinkFilterMode = SourceSinkFilterMode.UseAllButExcluded

    def merge(self, ssConfig):
        self.callbackSourceMode = ssConfig.callbackSourceMode
        self.enableLifecycleSources = ssConfig.enableLifecycleSources
        self.layoutMatchingMode = ssConfig.layoutMatchingMode

        self.sourceFilterMode = ssConfig.sourceFilterMode
        self.sinkFilterMode = ssConfig.sinkFilterMode

    def equals(self, obj):
        if self == obj:
            return True
        if obj is None:
            return False
        other = obj
        if self.callbackSourceMode != other.callbackSourceMode:
            return False
        if self.enableLifecycleSources != other.enableLifecycleSources:
            return False
        if self.layoutMatchingMode != other.layoutMatchingMode:
            return False
        if self.sinkFilterMode != other.sinkFilterMode:
            return False
        if self.sourceFilterMode != other.sourceFilterMode:
            return False
        return True


class PathConfiguration:

    def __init__(self):
        self.sequentialPathProcessing = False
        self.pathReconstructionMode = PathReconstructionMode.NoPaths
        self.pathBuildingAlgorithm = PathBuildingAlgorithm.ContextSensitive
        self.maxCallStackSize = 30
        self.maxPathLength = 75
        self.maxPathsPerAbstraction = 15
        self.pathReconstructionTimeout = 0
        self.pathReconstructionBatchSize = 5

    def merge(self, pathConfig):
        self.sequentialPathProcessing = pathConfig.sequentialPathProcessing
        self.pathReconstructionMode = pathConfig.pathReconstructionMode
        self.pathBuildingAlgorithm = pathConfig.pathBuildingAlgorithm
        self.maxCallStackSize = pathConfig.maxCallStackSize
        self.maxPathLength = pathConfig.maxPathLength
        self.maxPathsPerAbstraction = pathConfig.maxPathsPerAbstraction
        self.pathReconstructionTimeout = pathConfig.pathReconstructionTimeout
        self.pathReconstructionBatchSize = pathConfig.pathReconstructionBatchSize

    def mustKeepStatements(self):
        return self.pathReconstructionMode.reconstructPaths() or self.pathBuildingAlgorithm == PathBuildingAlgorithm.ContextSensitive

    def equals(self, obj):
        if self == obj:
            return True
        if obj is None:
            return False
        other = obj
        if self.maxCallStackSize != other.maxCallStackSize:
            return False
        if self.maxPathLength != other.maxPathLength:
            return False
        if self.maxPathsPerAbstraction != other.maxPathsPerAbstraction:
            return False
        if self.pathBuildingAlgorithm != other.pathBuildingAlgorithm:
            return False
        if self.pathReconstructionBatchSize != other.pathReconstructionBatchSize:
            return False
        if self.pathReconstructionMode != other.pathReconstructionMode:
            return False
        if self.pathReconstructionTimeout != other.pathReconstructionTimeout:
            return False
        if self.sequentialPathProcessing != other.sequentialPathProcessing:
            return False
        return True


class OutputConfiguration:
    def __init__(self):
        self.noPassedValues = False
        self.noCallGraphFraction = False
        self.maxCallersInOutputFile = 5
        self.resultSerializationTimeout = 0

    def merge(self, outputConfig):
        self.noPassedValues = outputConfig.noPassedValues
        self.noCallGraphFraction = outputConfig.noCallGraphFraction
        self.maxCallersInOutputFile = outputConfig.maxCallersInOutputFile
        self.resultSerializationTimeout = outputConfig.resultSerializationTimeout

    def equals(self, obj):
        if self == obj:
            return True
        if obj is None:
            return False
        other = obj
        if self.maxCallersInOutputFile != other.maxCallersInOutputFile:
            return False
        if self.noCallGraphFraction != other.noCallGraphFraction:
            return False
        if self.noPassedValues != other.noPassedValues:
            return False
        if self.resultSerializationTimeout != other.resultSerializationTimeout:
            return False
        return True


class SolverConfiguration:

    def __init__(self):
        self.dataFlowSolver = DataFlowSolver.ContextFlowSensitive
        self.maxJoinPointAbstractions = 10
        self.maxCalleesPerCallSite = 75
        self.maxAbstractionPathLength = 100

    def merge(self, solverConfig):
        self.dataFlowSolver = solverConfig.dataFlowSolver
        self.maxJoinPointAbstractions = solverConfig.maxJoinPointAbstractions
        self.maxCalleesPerCallSite = solverConfig.maxCalleesPerCallSite
        self.maxAbstractionPathLength = solverConfig.maxAbstractionPathLength

    def equals(self, obj):
        if self == obj:
            return True
        if obj is None:
            return False
        other = obj
        if self.dataFlowSolver != other.dataFlowSolver:
            return False
        if self.maxCalleesPerCallSite != other.maxCalleesPerCallSite:
            return False
        if self.maxJoinPointAbstractions != other.maxJoinPointAbstractions:
            return False
        if self.maxAbstractionPathLength != other.maxAbstractionPathLength:
            return False
        return True


class AccessPathConfiguration:

    def __init__(self):
        self.accessPathLength = 5
        self.useRecursiveAccessPaths = True
        self.useThisChainReduction = True
        self.useSameFieldReduction = True

    def merge(self, config):
        self.accessPathLength = config.accessPathLength
        self.useRecursiveAccessPaths = config.useRecursiveAccessPaths
        self.useThisChainReduction = config.useThisChainReduction
        self.useSameFieldReduction = config.useSameFieldReduction

    def equals(self, obj):
        if self == obj:
            return True
        if obj is None:
            return False
        other = obj
        if self.accessPathLength != other.accessPathLength:
            return False
        if self.useRecursiveAccessPaths != other.useRecursiveAccessPaths:
            return False
        if self.useSameFieldReduction != other.useSameFieldReduction:
            return False
        if self.useThisChainReduction != other.useThisChainReduction:
            return False
        return True


class InfoflowConfiguration:

    pathAgnosticResults = True
    oneResultPerAccessPath = False
    mergeNeighbors = False

    stopAfterFirstKFlows = 0
    implicitFlowMode = ImplicitFlowMode.NoImplicitFlows
    enableExceptions = True
    enableArrays = True
    enableArraySizeTainting = True
    flowSensitiveAliasing = True
    enableTypeChecking = True
    ignoreFlowsInSystemPackages = False
    excludeSootLibraryClasses = False
    maxThreadNum = -1
    writeOutputFiles = False
    logSourcesAndSinks = False
    enableReflection = False
    enableLineNumbers = False
    enableOriginalNames = False

    inspectSources = False
    inspectSinks = False

    pathConfiguration = PathConfiguration()
    outputConfiguration = OutputConfiguration()
    solverConfiguration = SolverConfiguration()
    accessPathConfiguration = AccessPathConfiguration()

    callgraphAlgorithm = CallgraphAlgorithm.AutomaticSelection
    aliasingAlgorithm = AliasingAlgorithm.FlowSensitive
    codeEliminationMode = CodeEliminationMode.PropagateConstants
    staticFieldTrackingMode = StaticFieldTrackingMode.ContextFlowSensitive
    sootIntegrationMode = SootIntegrationMode.CreateNewInstance

    taintAnalysisEnabled = True
    incrementalResultReporting = False
    dataFlowTimeout = 0
    memoryThreshold = 0.9
    oneSourceAtATime = False

    baseDirectory = ""

    def merge(self, config):
        self.stopAfterFirstKFlows = config.stopAfterFirstKFlows
        self.implicitFlowMode = config.implicitFlowMode
        self.enableExceptions = config.enableExceptions
        self.enableArrays = config.enableArrays
        self.enableArraySizeTainting = config.enableArraySizeTainting
        self.flowSensitiveAliasing = config.flowSensitiveAliasing
        self.enableTypeChecking = config.enableTypeChecking
        self.ignoreFlowsInSystemPackages = config.ignoreFlowsInSystemPackages
        self.excludeSootLibraryClasses = config.excludeSootLibraryClasses
        self.maxThreadNum = config.maxThreadNum
        self.writeOutputFiles = config.writeOutputFiles
        self.logSourcesAndSinks = config.logSourcesAndSinks
        self.enableReflection = config.enableReflection
        self.enableLineNumbers = config.enableLineNumbers
        self.enableOriginalNames = config.enableOriginalNames

        self.pathConfiguration.merge(config.pathConfiguration)
        self.outputConfiguration.merge(config.outputConfiguration)
        self.solverConfiguration.merge(config.solverConfiguration)
        self.accessPathConfiguration.merge(config.accessPathConfiguration)

        self.callgraphAlgorithm = config.callgraphAlgorithm
        self.aliasingAlgorithm = config.aliasingAlgorithm
        self.codeEliminationMode = config.codeEliminationMode
        self.staticFieldTrackingMode = config.staticFieldTrackingMode
        self.sootIntegrationMode = config.sootIntegrationMode

        self.inspectSources = config.inspectSources
        self.inspectSinks = config.inspectSinks

        self.taintAnalysisEnabled = config.writeOutputFiles
        self.incrementalResultReporting = config.incrementalResultReporting
        self.dataFlowTimeout = config.dataFlowTimeout
        self.memoryThreshold = config.memoryThreshold
        self.oneSourceAtATime = config.oneSourceAtATime

        self.baseDirectory = config.baseDirectory

    def printSummary(self):
        if self.staticFieldTrackingMode == StaticFieldTrackingMode._None:
            logger.warn("field tracking is disabled, results may be incomplete")
        if not self.flowSensitiveAliasing:
            logger.warn("Using flow-insensitive alias tracking, results may be imprecise")

        if self.implicitFlowMode == ImplicitFlowMode.AllImplicitFlows:
            logger.info("Implicit flow tracking is enabled")
        elif self.implicitFlowMode == ImplicitFlowMode.ArrayAccesses:
            logger.info("Tracking of implicit array accesses is enabled")
        elif self.implicitFlowMode == ImplicitFlowMode.NoImplicitFlows:
            logger.info("Implicit flow tracking is NOT enabled")

        if self.enableExceptions:
            logger.info("Exceptional flow tracking is enabled")
        else:
            logger.info("Exceptional flow tracking is NOT enabled")
        logger.info("Running with a maximum access path length of " + str(self.accessPathConfiguration.accessPathLength))
        if self.pathAgnosticResults:
            logger.info("Using path-agnostic result collection")
        else:
            logger.info("Using path-sensitive result collection")
        if self.accessPathConfiguration.useRecursiveAccessPaths:
            logger.info("Recursive access path shortening is enabled")
        else:
            logger.info("Recursive access path shortening is NOT enabled")
        logger.info("Taint analysis enabled: " + str(self.taintAnalysisEnabled))
        if self.oneSourceAtATime:
            logger.info("Running with one source at a time")
        logger.info("Using alias algorithm " + self.aliasingAlgorithm)
