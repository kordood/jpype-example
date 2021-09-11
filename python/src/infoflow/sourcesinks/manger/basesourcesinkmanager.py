import logging
from ...sootir.soot_class import SootClass
from ...sootir.soot_statement import SootStmt as Stmt
from ...infoflowmanager import InfoflowManager
from ...data.accesspath import AccessPath

from ...misc.pyenum import PyEnum
from ...infoflowconfiguration import InfoflowConfiguration

logger = logging.getLogger( __file__ )


class SimpleConstantValueProvider:

    @staticmethod
    def getValue(sm, stmt, value, type):
        return value


class BaseSourceSinkManager:
    GLOBAL_SIG = "--GLOBAL--"

    SourceType = PyEnum( 'NoSource', 'MethodCall', 'Callback', 'UISource' )


    def __init__(self, sources, sinks, callback_methods: dict=None, config: InfoflowConfiguration=None):
        self.source_sink_config = config.source_sink_configuration
        self.source_methods = None
        self.source_statements = None
        self.sink_methods = None
        self.sink_return_methods = None
        self.source_fields = None
        self.sink_fields = None
        self.sink_statements = None

        self.source_defs = dict()
        for am in sources:
            self.source_defs[self.getSignature( am )] = am

        self.sink_defs = dict()
        for am in sinks:
            self.sink_defs[self.getSignature( am )] = am

        self.callback_methods = dict()
        for cb in callback_methods:
            self.callback_methods[cb.getTargetMethod()] = cb

        logger.info("Created a SourceSinkManager with %d sources, %d sinks, and %d callback methods.",
                    len( self.source_defs ), len( self.sink_defs ), len( self.callback_methods ) )

        self.excluded_methods = dict()

        self.one_source_at_a_time = False
        self.osaat_type = self.SourceType.MethodCall
        self.osaat_iterator = None
        self.currentSource = None
        self.valueProvider = SimpleConstantValueProvider()

        self.interfacesOf = list()

    def load(self, sc: SootClass):
        interfaces = list()
        for i in sc.interfaces:
            interfaces.append( i )
            interfaces.extend( self.interfacesOf[i] )

        if sc.super_class:
            interfaces.extend( self.interfacesOf[sc.super_class] )

        if len( interfaces ) > 0:
            local_cache = {'key': sc, 'value': interfaces}
            self.interfacesOf.append(local_cache)
        return interfaces


    def getSignature(self, am):
        if isinstance( am, MethodSourceSinkDefinition ):
            methodSource = am
            return methodSource.method.signature
        elif isinstance( am, FieldSourceSinkDefinition ):
            fieldSource = am
            return fieldSource.field_signature
        elif isinstance( am, StatementSourceSinkDefinition ):
            return self.GLOBAL_SIG
        else:
            raise RuntimeError( "Invalid type of source/sink definition: %s" % am.getClass().getName() )

    def getSinkDefinition(self, sCallSite: Stmt, manager: InfoflowManager, ap: AccessPath):
        define = self.sink_statements.get( sCallSite )
        if define is not None:
            return define

        if sCallSite.containsInvokeExpr():
            callee = sCallSite.getInvokeExpr().method
            if not SystemClassHandler.v().isTaintVisible( ap, callee ):
                return None

            define = self.sink_methods.get( sCallSite.getInvokeExpr().method )
            if define is not None:
                return define

            subSig = callee.getSubSignature()

            for i in self.interfacesOf.getUnchecked( sCallSite.getInvokeExpr().method.getDeclaringClass() ):
                if i.declaresMethod( subSig ):
                    define = self.sink_methods.get( i.getMethod( subSig ) )
                    if define is not None:
                        return define

            for sm in manager.getICFG().getCalleesOfCallAt( sCallSite ):
                define = self.sink_methods.get( sm )
                if define is not None:
                    return define

            if callee.getDeclaringClass().isPhantom():
                define = self.findDefinitionInHierarchy( callee, self.sink_methods )
                if define is not None:
                    return define

            return None

        elif isinstance( sCallSite, AssignStmt ):
            assignStmt = sCallSite
            if isinstance( assignStmt.getLeftOp(), FieldRef ):
                fieldRef = assignStmt.getLeftOp()
                define = sinkFields.get( fieldRef.getField() )
                if define is not None:
                    return define

        elif isinstance( sCallSite, ReturnStmt ):
            return sinkReturnMethods.get( manager.getICFG().getMethodOf( sCallSite ) )

        return None

    def findDefinitionInHierarchy(self, callee: SootMethod, mehtod_map: dict):
        subSig = callee.getSubSignature()
        curClass = callee.getDeclaringClass()
        while curClass is not None:
            curMethod = curClass.getMethodUnsafe( subSig )
            if curMethod is not None:
                define = mehtod_map.get( curMethod )
                if define is not None:
                    mehtod_map.put( callee, define )
                    return define

            if curClass.hasSuperclass() and (curClass.isPhantom() or callee.hasTag( SimulatedCodeElementTag.TAG_NAME )):
                curClass = curClass.getSuperclass()
            else:
                curClass = None

        return None

    def getSinkInfo(self, sCallSite: Stmt, manager: InfoflowManager, ap: AccessPath):
        if excludedMethods.contains( manager.getICFG().getMethodOf( sCallSite ) ):
            return None
        if sCallSite.hasTag( SimulatedCodeElementTag.TAG_NAME ):
            return None

        define = getSinkDefinition( sCallSite, manager, ap )
        return None if define is None else SinkInfo( define )

    def getSourceInfo(self, sCallSite: Stmt, manager: InfoflowManager):

        if excludedMethods.contains( manager.getICFG().getMethodOf( sCallSite ) ):
            return None
        if sCallSite.hasTag( SimulatedCodeElementTag.TAG_NAME ):
            return None

        define = getSource( sCallSite, manager.getICFG() )
        return createSourceInfo( sCallSite, manager, define )

    def createSourceInfo(self, sCallSite: Stmt, manager: InfoflowManager, define):
        if define is None:
            return None

        if not sCallSite.containsInvokeExpr():
            if isinstance( sCallSite, DefinitionStmt ):
                defStmt = sCallSite
                return SourceInfo( define,
                                   manager.getAccessPathFactory().createAccessPath( defStmt.getLeftOp(), None, None,
                                                                                    None, True, False, True,
                                                                                    ArrayTaintType.ContentsAndLength,
                                                                                    False ) )

            return None

        iexpr = sCallSite.getInvokeExpr()
        returnType = iexpr.method.getReturnType()
        if isinstance( sCallSite DefinitionStmt) and returnType is not None and returnType != VoidType.v():
            defStmt = sCallSite
            return SourceInfo( define,
                               manager.getAccessPathFactory().createAccessPath( defStmt.getLeftOp(), None, None, None,
                                                                                True, False, True,
                                                                                ArrayTaintType.ContentsAndLength,
                                                                                False ) )
        elif isinstance( iexpr, InstanceInvokeExpr ) and returnType == VoidType.v():
            iinv = sCallSite.getInvokeExpr()
            return SourceInfo( define, manager.getAccessPathFactory().createAccessPath( iinv.getBase(), True ) )
        else:
            return None

    def getSourceMethod(self, method: SootMethod):
        if self.one_source_at_a_time and (osaatType != self.SourceType.MethodCall or currentSource != method):
            return None
        return self.source_methods.get( method )

    def getSourceDefinition(self, method: SootMethod):
        if self.one_source_at_a_time:
            if self.osaat_type == self.SourceType.MethodCall and currentSource == method:
                return self.source_methods.get( method )
            else:
                return None
        else:
            return self.source_methods.get( method )

    def getCallbackDefinition(self, method: SootMethod):
        if self.one_source_at_a_time:
            if self.osaat_type == self.SourceType.Callback and currentSource == method:
                return self.callback_methods.get( method )
            else:
                return None
        else:
            return self.callback_methods.get( method )

    def getSource(self, sCallSite: Stmt, cfg: IInfoflowCFG):
        assert cfg is not None
        assert isinstance( cfg, BiDiInterproceduralCFG )

        define = sourceStatements.get( sCallSite )
        if define is not None:
            return define

        define = None
        if (not self.one_source_at_a_time or self.osaat_type == self.SourceType.MethodCall) and sCallSite.containsInvokeExpr():
            callee = sCallSite.getInvokeExpr().method
            define = self.getSourceDefinition( callee )
            if define is not None:
                return define

            subSig = callee.getSubSignature()
            for i in self.load( callee.getDeclaringClass() ):
                m = i.getMethodUnsafe( subSig )
                if m is not None:
                    define = self.getSourceDefinition( m )
                    if define is not None:
                        return define

            for sm in cfg.getCalleesOfCallAt( sCallSite ):
                define = self.getSourceDefinition( sm )
                if define is not None:
                    return define

            if callee.getDeclaringClass().isPhantom() or callee.hasTag( SimulatedCodeElementTag.TAG_NAME ):
                define = self.findDefinitionInHierarchy( callee, self.source_methods )
                if define is not None:
                    return define

        if (not self.one_source_at_a_time or self.osaat_type == self.SourceType.UISource):
            define = self.getUISourceDefinition( sCallSite, cfg )
            if define is not None:
                return define

        define = self.checkCallbackParamSource( sCallSite, cfg )
        if define is not None:
            return define

        define = self.checkFieldSource( sCallSite, cfg )
        if define is not None:
            return define

        return None

    def checkFieldSource(self, stmt: Stmt, cfg: IInfoflowCFG):
        if isinstance( stmt, AssignStmt ):
            assignStmt = stmt
            if isinstance( assignStmt.getRightOp(), FieldRef ):
                fieldRef = assignStmt.getRightOp()
                return self.source_fields.get( fieldRef.getField() )
            return None

    def checkCallbackParamSource(self, sCallSite: Stmt, cfg: IInfoflowCFG):
        if self.source_sink_config.callback_source_mode == CallbackSourceMode.NoParametersAsSources:
            return None
        if self.one_source_at_a_time and self.osaat_type != self.SourceType.Callback:
            return None

        if not isinstance( sCallSite, IdentityStmt ):
            return None
        identityStmt = sCallSite
        if not isinstance( identityStmt.getRightOp(), ParameterRef ):
            return None
        paramRef = identityStmt.getRightOp()

        parentMethod = cfg.getMethodOf( sCallSite )
        if parentMethod is None:
            return None
        if not self.source_sink_config.getEnableLifecycleSources() and isEntryPointMethod( parentMethod ):
            return None

        define = getCallbackDefinition( parentMethod )
        if define is None:
            return None

        if self.source_sink_config.getCallbackSourceMode() == CallbackSourceMode.AllParametersAsSources:
            return MethodSourceSinkDefinition.createParameterSource( paramRef.getIndex(), CallType.Callback )

        sourceSinkDef = self.source_methods.get( define.getParentMethod() )
        if isinstance( sourceSinkDef, MethodSourceSinkDefinition ):
            methodDef = sourceSinkDef
            if self.source_sink_config.getCallbackSourceMode() == CallbackSourceMode.SourceListOnly and sourceSinkDef is not None
                methodParamDefs = methodDef.getParameters()
                if methodParamDefs is not None and methodParamDefs.length > paramRef.getIndex():
                    apTuples = methodDef.getParameters()[paramRef.getIndex()]
                    if apTuples is not None and not apTuples.isEmpty():
                        for curTuple in apTuples:
                            if curTuple.getSourceSinkType().isSource():
                                return sourceSinkDef

        return None

    def isEntryPointMethod(self, method):

    def getUISourceDefinition(self, sCallSite: Stmt, cfg: IInfoflowCFG):
        return None

    def initialize(self):
        if sourceDefs is not None:
            sourceMethods = dict()
            self.source_fields = dict()
            sourceStatements = dict()
            for entry in sourceDefs:
                sourceSinkDef = entry.getO2()
                if isinstance( sourceSinkDef, MethodSourceSinkDefinition ):
                    method = sourceSinkDef.method
                    returnType = method.getReturnType()

                    if returnType is None or returnType.isEmpty():
                        className = method.getClassName()
                        subSignatureWithoutReturnType = sourceSinkDef.method.getSubSignature()
                        sootMethod = grabMethodWithoutReturn( className, subSignatureWithoutReturnType )

                        if sootMethod is not None:
                            sourceMethods.put( sootMethod, sourceSinkDef )
                    else:
                        sm = Scene.v().grabMethod( entry.getO1() )
                        if sm is not None:
                            sourceMethods.put( sm, sourceSinkDef )

                elif isinstance( sourceSinkDef, FieldSourceSinkDefinition ):
                    sf = Scene.v().grabField( entry.getO1() )
                    if sf is not None:
                        self.source_fields.put( sf, sourceSinkDef )
                elif isinstance( sourceSinkDef, StatementSourceSinkDefinition ):
                    StatementSourceSinkDefinition
                    sssd = (StatementSourceSinkDefinition)
                    sourceSinkDef
                    sourceStatements.put( sssd.getStmt(), sssd )

            sourceDefs = None

        if sinkDefs is not None:
            sinkMethods = dict()
            sinkFields = dict()
            sinkReturnMethods = dict()
            sinkStatements = dict()
            for entry in sinkDefs:
                sourceSinkDef = entry.getO2()
                if isinstance( sourceSinkDef, MethodSourceSinkDefinition ):
                    methodSourceSinkDef = (sourceSinkDef)
                    if methodSourceSinkDef.getCallType() == CallType.Return:
                        SootMethodAndClass
                        method = methodSourceSinkDef.method
                        m = Scene.v().grabMethod( method.signature )
                        if m is not None:
                            sinkReturnMethods.put( m, methodSourceSinkDef )
                    else:
                        SootMethodAndClass
                        method = methodSourceSinkDef.method
                        returnType = method.getReturnType()
                        isMethodWithoutReturnType = returnType is None or returnType.isEmpty()
                        if isMethodWithoutReturnType:
                            className = method.getClassName()
                            subSignatureWithoutReturnType = ((sourceSinkDef)
                                                             .method.getSubSignature())
                            sootMethod = grabMethodWithoutReturn( className, subSignatureWithoutReturnType )
                            if sootMethod is not None:
                                sinkMethods.put( sootMethod, sourceSinkDef )
                        else:
                            sm = Scene.v().grabMethod( entry.getO1() )
                            if sm is not None:
                                sinkMethods.put( sm, entry.getO2() )

                elif isinstance( sourceSinkDef, FieldSourceSinkDefinition ):
                    sf = Scene.v().grabField( entry.getO1() )
                    if sf is not None:
                        sinkFields.put( sf, sourceSinkDef )
                elif isinstance( sourceSinkDef, StatementSourceSinkDefinition ):
                    StatementSourceSinkDefinition
                    sssd = (StatementSourceSinkDefinition)
                    sourceSinkDef
                    sinkStatements.put( sssd.getStmt(), sssd )

            sinkDefs = None

    def grabMethodWithoutReturn(self, sootClassName: str, subSignature: str):
        sootClass = Scene.v().getSootClassUnsafe( sootClassName )
        if sootClass is None:
            return None

        sootMethods = None
        if sootClass.resolvingLevel() != DANGLING:
            sootMethods = sootClass.getMethods()

            for s in sootMethods:
                tempSignature = s.getSubSignature().split( " " )

                if tempSignature.length == 2:
                    if tempSignature[1].equals( subSignature ):
                        return s

        return None

    def isOneSourceAtATimeEnabled(self):
        return self.one_source_at_a_time

    def resetCurrentSource(self):
        self.osaat_iterator = self.source_methods.keys()
        self.osaat_type = self.SourceType.MethodCall

    def nextSource(self):
        if self.osaat_type == self.SourceType.MethodCall or self.osaat_type == self.SourceType.Callback:
            currentSource = self.osaat_iterator.next()

    def hasNextSource(self):
        if self.osaat_type == self.SourceType.MethodCall:
            if self.osaat_iterator.hasNext():
                return True
            else:
                self.osaat_type = self.SourceType.Callback
                self.osaat_iterator = self.callback_methods.keySet().iterator()
                return hasNextSource()

        elif self.osaat_type == self.SourceType.Callback:
            if self.osaat_iterator.hasNext():
                return True
            else:
                self.osaat_type = self.SourceType.UISource
                return True

        elif self.osaat_type == self.SourceType.UISource:
            self.osaat_type = self.SourceType.NoSource
            return False

        return False

    def excludeMethod(self, toExclude):
        self.excluded_methods.add( toExclude )
