import Scene
import Stmt, StaticFieldRef
import PathEdge


class GlobalTaintManager:
    def __init__(self, solvers):
        self.globalTaintState = set()
        self.solvers = solvers

    def add_to_global_taint_state(self, abs):
        if self.globalTaintState.add(abs) and self.solvers is not None and not self.solvers.is_empty():
            injection_points = set()
            method_listener = Scene.v().getReachableMethods().listener()
            for mmoc in method_listener:
                if mmoc is None:
                    continue
                sm = mmoc.method()
                if sm is not None and sm.isConcrete():
                    for u in sm.getActiveBody().getUnits():
                        if isinstance(u, Stmt):
                            stmt = u
                            for vb in stmt.getUseBoxes():
                                if isinstance(vb.getValue(), StaticFieldRef):
                                    field_ref = vb.getValue()
                                    if abs.getAccessPath().first_field_matches( field_ref.get_field() ):
                                        injection_points.add(stmt)

            if len(injection_points) > 0:
                for solver in self.solvers:
                    for stmt in injection_points:
                        solver.processEdge(PathEdge(solver.getTabulationProblem().zeroValue(), stmt, abs))

            return True
        return False
