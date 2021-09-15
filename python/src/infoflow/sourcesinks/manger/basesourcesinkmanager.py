import Scene
import MethodSourceSinkDefinition
import FieldSourceSinkDefinition
import StatementSourceSinkDefinition
import SinkInfo, SourceInfo
import VoidType, CallType


import logging
from ...sootir.soot_class import SootClass, SootMethod
from ...sootir.soot_value import SootInstanceFieldRef as FieldRef, SootParamRef as ParameterRef
from ...sootir.soot_statement import SootStmt as Stmt, AssignStmt, ReturnStmt, DefinitionStmt, IdentityStmt
from ...sootir.soot_expr import SootInvokeExpr as InstanceInvokeExpr
from ...infoflowmanager import InfoflowManager
from ...data.accesspath import AccessPath, ArrayTaintType

from ...solver.cfg.infoflowcfg import InfoflowCFG
from ...misc.pyenum import PyEnum
from ...util.systemclasshandler import SystemClassHandler
from ...infoflowconfiguration import InfoflowConfiguration, CallbackSourceMode

logger = logging.getLogger( __file__ )


class SimpleConstantValueProvider:

    @staticmethod
    def getValue(sm, stmt, value, type):
        return value


class BaseSourceSinkManager:
    """
    4 fields are in soot class
    """
    DANGLING = 0
    HIERARCHY = 1
    SIGNATURES = 2
    BODIES = 3

    GLOBAL_SIG = "--GLOBAL--"

    SourceType = PyEnum( 'NoSource', 'MethodCall', 'Callback', 'UISource' )

    def __init__(self, sources, sinks, callback_methods: dict=None, config: InfoflowConfiguration=None):
        self.config = config
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
            self.source_defs[self.get_signature( am )] = am

        self.sink_defs = dict()
        for am in sinks:
            self.sink_defs[self.get_signature( am )] = am

        self.callback_methods = dict()
        for cb in callback_methods:
            self.callback_methods[cb.getTargetMethod()] = cb

        logger.info("Created a SourceSinkManager with %d sources, %d sinks, and %d callback methods.",
                    len( self.source_defs ), len( self.sink_defs ), len( self.callback_methods ) )

        self.excluded_methods = list()

        self.one_source_at_a_time = False
        self.osaat_type = self.SourceType.MethodCall
        self.osaat_iterator = None
        self.current_source = None
        self.value_provider = SimpleConstantValueProvider()

        self.interfaces_of = list()

    def load(self, sc: SootClass):
        interfaces = list()
        for i in sc.interfaces:
            interfaces.append( i )
            interfaces.extend( self.interfaces_of[i] )

        if sc.super_class:
            interfaces.extend( self.interfaces_of[sc.super_class] )

        if len( interfaces ) > 0:
            local_cache = {'key': sc, 'value': interfaces}
            self.interfaces_of.append( local_cache )
        return interfaces

    def get_signature(self, am):
        if isinstance( am, MethodSourceSinkDefinition ):
            method_source = am
            return method_source.method.signature
        elif isinstance( am, FieldSourceSinkDefinition ):
            field_source = am
            return field_source.field_signature
        elif isinstance( am, StatementSourceSinkDefinition ):
            return self.GLOBAL_SIG
        else:
            raise RuntimeError( "Invalid type of source/sink definition: %s" % am.getClass().getName() )

    def get_sink_definition(self, s_call_site, manager: InfoflowManager, ap: AccessPath):
        define = self.sink_statements.get( s_call_site )
        if define is not None:
            return define

        if s_call_site.containsInvokeExpr:
            callee = s_call_site.getInvokeExpr().method
            if not SystemClassHandler.v().isTaintVisible( ap, callee ):
                return None

            define = self.sink_methods.get( s_call_site.getInvokeExpr().method )
            if define is not None:
                return define

            sub_sig = callee.name

            for i in self.load( s_call_site.getInvokeExpr().method.class_name ):
                if i.declaresMethod( sub_sig ):
                    define = self.sink_methods.get( i.getMethod( sub_sig ) )
                    if define is not None:
                        return define

            for sm in manager.icfg.get_callees_of_call_at( s_call_site ):
                define = self.sink_methods.get( sm )
                if define is not None:
                    return define

            if callee.class_name.isPhantom():
                define = self.find_definition_in_hierarchy( callee, self.sink_methods )
                if define is not None:
                    return define

            return None

        elif isinstance( s_call_site, AssignStmt ):
            assign_stmt = s_call_site
            if isinstance( assign_stmt.left_op, FieldRef ):
                field_ref = assign_stmt.left_op
                define = self.sink_fields.get( field_ref.field )
                if define is not None:
                    return define

        elif isinstance( s_call_site, ReturnStmt ):
            return self.sink_return_methods.get( manager.icfg.get_method_of( s_call_site ) )

        return None

    def find_definition_in_hierarchy(self, callee: SootMethod, mehtod_map: dict):
        sub_sig = callee.name
        cur_class = callee.class_name
        while cur_class is not None:
            cur_method = cur_class.getMethodUnsafe( sub_sig )
            if cur_method is not None:
                define = mehtod_map.get( cur_method )
                if define is not None:
                    mehtod_map[callee] = define
                    return define

            if cur_class.hasSuperclass() and cur_class.isPhantom():
                cur_class = cur_class.super_class()
            else:
                cur_class = None

        return None

    def get_sink_info(self, s_call_site, manager: InfoflowManager, ap: AccessPath):
        if manager.icfg.get_method_of( s_call_site ) in self.excluded_methods:
            return None
        """
        if s_call_site.hasTag( SimulatedCodeElementTag.TAG_NAME ):
            return None
        """

        define = self.get_sink_definition( s_call_site, manager, ap )
        return None if define is None else SinkInfo( define )

    def get_source_info(self, s_call_site, manager: InfoflowManager):
        if manager.icfg.get_method_of( s_call_site ) in self.excluded_methods:
            return None
        """
        if s_call_site.hasTag( SimulatedCodeElementTag.TAG_NAME ):
            return None
        """
        define = self.get_source( s_call_site, manager.icfg )
        return self.create_source_info( s_call_site, manager, define )

    def create_source_info(self, s_call_site, manager: InfoflowManager, define):
        if define is None:
            return None

        if not s_call_site.containsInvokeExpr():
            if isinstance( s_call_site, DefinitionStmt ):
                def_stmt = s_call_site
                return SourceInfo( define,
                                   manager.access_path_factory.create_access_path( def_stmt.left_op, None, None,
                                                                                    None, True, False, True,
                                                                                    ArrayTaintType.ContentsAndLength,
                                                                                    False ) )

            return None

        iexpr = s_call_site.getInvokeExpr()
        return_type = iexpr.method.ret
        if isinstance( s_call_site, DefinitionStmt) and return_type is not None and return_type != VoidType.v():
            def_stmt = s_call_site
            return SourceInfo( define,
                               manager.access_path_factory.createAccessPath( def_stmt.left_op, None, None, None,
                                                                                True, False, True,
                                                                                ArrayTaintType.ContentsAndLength,
                                                                                False ) )
        elif isinstance( iexpr, InstanceInvokeExpr ) and return_type == VoidType.v():
            iinv = s_call_site.getInvokeExpr()
            return SourceInfo( define, manager.access_path_factory.createAccessPath( iinv.base, True ) )
        else:
            return None

    def get_source_method(self, method: SootMethod):
        if self.one_source_at_a_time and (self.osaat_type != self.SourceType.MethodCall or self.current_source != method):
            return None
        return self.source_methods.get( method )

    def get_source_definition(self, method: SootMethod):
        if self.one_source_at_a_time:
            if self.osaat_type == self.SourceType.MethodCall and self.current_source == method:
                return self.source_methods.get( method )
            else:
                return None
        else:
            return self.source_methods.get( method )

    def get_callback_definition(self, method: SootMethod):
        if self.one_source_at_a_time:
            if self.osaat_type == self.SourceType.Callback and self.current_source == method:
                return self.callback_methods.get( method )
            else:
                return None
        else:
            return self.callback_methods.get( method )

    def get_source(self, s_call_site, cfg: InfoflowCFG):
        assert cfg is not None

        define = self.source_statements.get( s_call_site )
        if define is not None:
            return define

        if (not self.one_source_at_a_time or self.osaat_type == self.SourceType.MethodCall) and s_call_site.containsInvokeExpr():
            callee = s_call_site.getInvokeExpr().method
            define = self.get_source_definition( callee )
            if define is not None:
                return define

            sub_sig = callee.name
            for i in self.load( callee.class_name ):
                m = i.getMethodUnsafe( sub_sig )
                if m is not None:
                    define = self.get_source_definition( m )
                    if define is not None:
                        return define

            for sm in cfg.getCalleesOfCallAt( s_call_site ):
                define = self.get_source_definition( sm )
                if define is not None:
                    return define

            if callee.class_name.isPhantom():
                define = self.find_definition_in_hierarchy( callee, self.source_methods )
                if define is not None:
                    return define

        if not self.one_source_at_a_time or self.osaat_type == self.SourceType.UISource:
            define = self.get_ui_source_definition( s_call_site, cfg )
            if define is not None:
                return define

        define = self.check_callback_param_source( s_call_site, cfg )
        if define is not None:
            return define

        define = self.check_field_source( s_call_site, cfg )
        if define is not None:
            return define

        return None

    def check_field_source(self, stmt: Stmt, cfg: InfoflowCFG):
        if isinstance( stmt, AssignStmt ):
            assign_stmt = stmt
            if isinstance( assign_stmt.right_op, FieldRef ):
                field_ref = assign_stmt.right_op
                return self.source_fields.get( field_ref.field )
            return None

    def check_callback_param_source(self, s_call_site, cfg: InfoflowCFG):
        if self.source_sink_config.callback_source_mode == CallbackSourceMode.NoParametersAsSources:
            return None
        if self.one_source_at_a_time and self.osaat_type != self.SourceType.Callback:
            return None

        if not isinstance( s_call_site, IdentityStmt ):
            return None
        identity_stmt = s_call_site
        if not isinstance( identity_stmt.right_op, ParameterRef ):
            return None
        param_ref = identity_stmt.right_op

        parent_method = cfg.get_method_of( s_call_site )
        if parent_method is None:
            return None
        if not self.source_sink_config.getEnableLifecycleSources() and self.is_entry_point_method( parent_method ):
            return None

        define = self.get_callback_definition( parent_method )
        if define is None:
            return None

        if self.source_sink_config.getCallbackSourceMode() == CallbackSourceMode.AllParametersAsSources:
            return MethodSourceSinkDefinition.createParameterSource( param_ref.index, CallType.Callback )

        source_sink_def = self.source_methods.get( define.getParentMethod() )
        if isinstance( source_sink_def, MethodSourceSinkDefinition ):
            method_def = source_sink_def
            if self.source_sink_config.getCallbackSourceMode() == CallbackSourceMode.SourceListOnly \
                    and source_sink_def is not None:
                method_param_defs = method_def.getParameters()
                if method_param_defs is not None and len(method_param_defs) > param_ref.index:
                    ap_tuples = method_def.getParameters()[param_ref.index]
                    if ap_tuples is not None and not ap_tuples.isEmpty():
                        for curTuple in ap_tuples:
                            if curTuple.getSourceSinkType().isSource():
                                return source_sink_def

        return None

    def is_entry_point_method(self, method):
        pass

    def get_ui_source_definition(self, s_call_site, cfg: InfoflowCFG):
        return None

    def initialize(self):
        if self.source_defs is not None:
            source_methods = dict()
            self.source_fields = dict()
            source_statements = dict()
            for entry in self.source_defs:
                source_sink_def = entry.getO2()
                if isinstance( source_sink_def, MethodSourceSinkDefinition ):
                    method = source_sink_def.method
                    return_type = method.ret

                    if return_type is None or return_type.isEmpty():
                        class_name = method.class_name
                        sub_signature_without_return_type = source_sink_def.method.name
                        soot_method = self.grab_method_without_return( class_name, sub_signature_without_return_type )

                        if soot_method is not None:
                            source_methods[soot_method] = source_sink_def
                    else:
                        sm = Scene.v().grabMethod( entry.getO1() )
                        if sm is not None:
                            source_methods[sm] = source_sink_def

                elif isinstance( source_sink_def, FieldSourceSinkDefinition ):
                    sf = Scene.v().grabField( entry.getO1() )
                    if sf is not None:
                        self.source_fields[sf] = source_sink_def
                elif isinstance( source_sink_def, StatementSourceSinkDefinition ):
                    sssd = source_sink_def
                    source_statements[sssd.stmt] = sssd

        if self.sink_defs is not None:
            sink_methods = dict()
            sink_fields = dict()
            sink_return_methods = dict()
            sink_statements = dict()
            for entry in self.sink_defs:
                source_sink_def = entry.getO2()
                if isinstance( source_sink_def, MethodSourceSinkDefinition ):
                    method_source_sink_def = source_sink_def
                    if method_source_sink_def.getCallType() == CallType.Return:
                        method = method_source_sink_def.method
                        m = Scene.v().grabMethod( method.signature )
                        if m is not None:
                            sink_return_methods[m] = method_source_sink_def
                    else:
                        method = method_source_sink_def.method
                        return_type = method.ret
                        is_method_without_return_type = return_type is None or return_type.isEmpty()
                        if is_method_without_return_type:
                            class_name = method.class_name
                            sub_signature_without_return_type = source_sink_def.method.name
                            soot_method = self.grab_method_without_return( class_name, sub_signature_without_return_type )
                            if soot_method is not None:
                                sink_methods[soot_method] = source_sink_def
                        else:
                            sm = Scene.v().grabMethod( entry.getO1() )
                            if sm is not None:
                                sink_methods[sm] = entry.getO2()
                elif isinstance( source_sink_def, FieldSourceSinkDefinition ):
                    sf = Scene.v().grabField( entry.getO1() )
                    if sf is not None:
                        sink_fields[sf] = source_sink_def
                elif isinstance( source_sink_def, StatementSourceSinkDefinition ):
                    sssd = source_sink_def
                    sink_statements[sssd.stmt] = sssd

            self.sink_defs = None

    def grab_method_without_return(self, soot_class_name: str, sub_signature: str):
        soot_class = Scene.v().getSootClassUnsafe( soot_class_name )
        if soot_class is None:
            return None

        if soot_class.resolvingLevel() != self.DANGLING:
            soot_methods = soot_class.getMethods()

            for s in soot_methods:
                temp_signature = s.name.split( " " )

                if len(temp_signature) == 2:
                    if temp_signature[1].equals( sub_signature ):
                        return s

        return None

    def is_one_source_at_a_time_enabled(self):
        return self.one_source_at_a_time

    def reset_current_source(self):
        self.osaat_iterator = self.source_methods.keys()
        self.osaat_type = self.SourceType.MethodCall

    def next_source(self):
        if self.osaat_type == self.SourceType.MethodCall or self.osaat_type == self.SourceType.Callback:
            self.current_source = self.osaat_iterator[0]
            self.osaat_iterator = self.osaat_iterator[1:]

    def has_next_source(self):
        if self.osaat_type == self.SourceType.MethodCall:
            if len(self.osaat_iterator) > 2:
                return True
            else:
                self.osaat_type = self.SourceType.Callback
                self.osaat_iterator = self.callback_methods.keys()
                return self.has_next_source()

        elif self.osaat_type == self.SourceType.Callback:
            if len(self.osaat_iterator) > 2:
                return True
            else:
                self.osaat_type = self.SourceType.UISource
                return True

        elif self.osaat_type == self.SourceType.UISource:
            self.osaat_type = self.SourceType.NoSource
            return False

        return False

    def exclude_method(self, to_exclude):
        self.excluded_methods.append( to_exclude )
