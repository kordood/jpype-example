import logging
from ..sootir.soot_statement import ReturnStmt
from ..sootir.soot_statement import ReturnVoidStmt
from .abstraction import Abstraction
from .accesspath import AccessPath
from ..misc.pyenum import PyEnum

logger = logging.getLogger( __file__ )

PathDataErasureMode = PyEnum( 'EraseNothing', 'KeepOnlyContextData', 'EraseAll' )


class FlowDroidMemoryManager:

    class AbstractionCacheKey:

        def __init__(self, _abs: Abstraction):
            self.abs = _abs

        def __eq__(self, other):
            if self == other:
                return True
            if other is None:
                return False

            if not self.abs == other.abs:
                return False
            if self.abs.predecessor != other.abs.predecessor:
                return False
            if self.abs.current_stmt != other.abs.current_stmt:
                return False
            if self.abs.corresponding_call_site != other.abs.corresponding_call_site:
                return False

            return True

    def __init__(self, tracing_enabled: bool =False, erase_path_data =PathDataErasureMode.EraseNothing):
        self.ap_cache = list()
        self.abs_cache = list()
        self.reuse_counter = int
        self.use_abstraction_cache = False

        self.tracing_enabled = tracing_enabled
        self.erase_path_data = erase_path_data

        logger.info( "Initializing FlowDroid memory manager..." )
        if self.tracing_enabled:
            logger.info( "FDMM: Tracing enabled. This may negatively affect performance." )
        if self.erase_path_data != PathDataErasureMode.EraseNothing:
            logger.info( "FDMM: Path data erasure enabled" )

    def get_cached_access_path(self, ap: AccessPath):
        old_ap = self.ap_cache.putIfAbsent( ap, ap )

        if old_ap is None:
            return ap

        if self.tracing_enabled and old_ap != ap:
            self.reuse_counter+=1
        return old_ap

    def get_cached_abstraction(self, abs: Abstraction):
        old_abs = self.abs_cache.putIfAbsent( self.AbstractionCacheKey( abs ), abs )
        if old_abs is not None and old_abs != abs:
            if self.tracing_enabled:
                self.reuse_counter+=1
        return old_abs

    def handle_memory_object(self, obj):
        return obj

    def handle_generated_memory_object(self, _input: Abstraction, output: Abstraction):
        if _input == output:
            return output

        if _input == output:
            if output.current_stmt is None or _input.current_stmt == output.current_stmt:
                return _input

        new_ap = self.get_cached_access_path( output.access_path )
        output.access_path = new_ap

        if self.erase_path_data != PathDataErasureMode.EraseNothing:
            cur_abs = output.predecessor
            while cur_abs is not None and cur_abs.neighbors is None:
                pred_pred = cur_abs.predecessor
                if pred_pred is not None:
                    if pred_pred == output:
                        output = pred_pred

                cur_abs = pred_pred
        self.erase_path_data( output )

        if self.use_abstraction_cache:
            cached_abs = self.get_cached_abstraction( output )
            if cached_abs is not None:
                return cached_abs

        return output

    def erase_path_data(self, output:Abstraction):
        if self.erase_path_data != PathDataErasureMode.EraseNothing:

            if self.erase_path_data == PathDataErasureMode.EraseAll:
                output.current_stmt = None
                output.corresponding_call_site = None

        elif self.erase_path_data == PathDataErasureMode.KeepOnlyContextData \
                and output.corresponding_call_site == output.current_stmt:
            output.current_stmt = None
            output.corresponding_call_site = None

        elif self.erase_path_data == PathDataErasureMode.KeepOnlyContextData \
                and output.corresponding_call_site is None \
                and output.current_stmt is not None:
            if output.corresponding_call_site is None and output.current_stmt is not None \
                    and not output.current_stmt.containsInvokeExpr() \
                    and not isinstance(output.current_stmt, ReturnStmt) \
                    and not isinstance(output.current_stmt, ReturnVoidStmt):
                output.current_stmt = None
                output.corresponding_call_site = None

    def is_essential_join_point(self, _abs: Abstraction, related_call_site):
        return related_call_site is not None and self.erase_path_data != PathDataErasureMode.EraseAll
