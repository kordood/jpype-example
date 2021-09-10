import logging

from .resultsourceinfo import ResultSourceInfo
from .resultsinkinfo import ResultSinkInfo
from .dataflowresult import DataFlowResult

logger = logging.getLogger(__file__)


class InfoflowResults:
    TERMINATION_SUCCESS = 0
    TERMINATION_DATA_FLOW_TIMEOUT = 1
    TERMINATION_DATA_FLOW_OOM = 2
    TERMINATION_PATH_RECONSTRUCTION_TIMEOUT = 4
    TERMINATION_PATH_RECONSTRUCTION_OOM = 8

    def __init__(self):
        self.results = None
        self.performance_data = None
        self.exceptions = None
        self.termination_state = InfoflowResults.TERMINATION_SUCCESS

    def add_exception(self, ex):
        if self.exceptions is None:
            if self.exceptions is None:
                self.exceptions = list()
        self.exceptions.append(ex)

    def num_connections(self):
        num = 0
        if self.results is not None:
            for sink in self.results.keySet():
                num += self.results.get(sink).size()
        return num

    def contains_sink(self, sink):
        for si in self.results.keySet():
            if si.stmt == sink:
                return True
        return False

    def contains_sink_method(self, sink_signature):
        return len(self.find_sink_by_method_signature(sink_signature)) > 0

    def add_result(self, sink_definition=None, sink=None, sink_stmt=None, source_definition=None, source=None,
                   source_stmt=None, user_data=None, propagation_path=None, propagation_access_path=None, res=None):

        if propagation_access_path is not None:
            source_obj = ResultSourceInfo(source_definition, source, source_stmt, user_data, propagation_path,
                                         propagation_access_path)
            sink_obj = ResultSinkInfo(sink_definition, sink, sink_stmt)

            self.add_result(sink=sink_obj, source=source_obj)
            return source_obj, sink_obj

        elif propagation_path is not None and propagation_access_path is None:
            stmt_path = list()
            ap_path = list()
            for path_abs in propagation_path:
                if path_abs.getCurrentStmt() is not None:
                    stmt_path.append(path_abs.getCurrentStmt())
                    ap_path.append(path_abs.getAccessPath())

                    return self.add_result(sink_definition=sink_definition, sink=sink, sink_stmt=sink_stmt, source_definition=source_definition, source=source, source_stmt=source_stmt,
                                           user_data=user_data, propagation_path=stmt_path, propagation_access_path=ap_path)
        elif res is not None:
            if res is not None:
                self.add_result(sink=res.sink, source=res.source)
        elif sink is not None and source is not None and propagation_path is None and propagation_access_path is None:
            if self.results is None:
                self.results = set()

            self.results.put(sink, source)

        else:
            return self.add_result(sink=ResultSinkInfo(sink_definition, sink, sink_stmt),
                                   source=ResultSourceInfo(source_definition, source, source_stmt))

    def add_all(self, results):
        if results is None:
            return

        if results.getExceptions() is not None:
            for e in results.getExceptions():
                self.add_exception(e)

        if not results.isEmpty() and not results.getResults().is_empty():
            for sink in results.getResults().keySet():
                for source in results.getResults().get(sink):
                    self.add_result(sink=sink, source=source)

        if results.performanceData is not None:
            if self.performance_data is None:
                self.performance_data = results.performanceData
            else:
                self.performance_data.add(results.performanceData)

        self.termination_state |= results.terminationState

    def get_result_set(self):
        if self.results is None or self.results.is_empty():
            return None

        _set = set(self.results.size() * 10)
        for sink in self.results.keySet():
            for source in self.results.get(sink):
                _set.add(DataFlowResult(source, sink))

        return _set

    def isPathBetween(self, sink, source):
        if self.results is None:
            return False

        sources = None
        for s_i in self.results.keySet():
            if s_i.stmt == sink:
                sources = self.results.get(s_i)
                break

        if sources is None:
            return False
        for src in sources:
            if src.access_path == source:
                return True
        return False

    def is_path_between(self, sink, source):
        if self.results is None:
            return False

        for si in self.results.keySet():
            if str(si.access_path.value) == sink:
                sources = self.results.get(si)
                for src in sources:
                    if source in str(src.stmt):
                        return True

        return False

    def is_path_between_methods(self, sink_signature, source_signature):
        sink_vals = self.find_sink_by_method_signature(sink_signature)
        for si in sink_vals:
            sources = self.results.get(si)
            if sources is None:
                return False
            for src in sources:
                if src.stmt.containsInvokeExpr():
                    expr = src.stmt.invoke_expr
                    if expr.method.signature == source_signature:
                        return True

        return False

    def find_sink_by_method_signature(self, sink_signature):
        if self.results is None:
            return list()

        sink_vals = list()
        for si in self.results.keySet():
            if si.stmt.containsInvokeExpr():
                expr = si.stmt.invoke_expr
                if expr.method.signature == sink_signature:
                    sink_vals.append(si)

        return sink_vals

    def clear(self):
        self.results = None

    def __eq__(self, other):
        if self == other:
            return True
        if other is None:
            return False
        if self.exceptions is None:
            if other.exceptions is not None:
                return False
            elif not self.exceptions == other.exceptions:
                return False
        if self.results is None:
            if other.results is not None:
                return False
            elif not self.results == other.results:
                return False
        return True