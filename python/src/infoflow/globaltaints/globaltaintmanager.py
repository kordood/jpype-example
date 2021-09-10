import Scene
import Stmt

from ..sootir.soot_value import SootStaticFieldRef

from ..data.abstraction import Abstraction
from ..solver.pathedge import PathEdge


class GlobalTaintManager:
    def __init__(self, solvers:dict):
        self.global_taint_state = list()
        self.solvers = solvers

    def add_to_global_taint_state(self, abstraction:Abstraction):
        if self.global_taint_state.append(abstraction) and self.solvers is not None and len(self.solvers) > 0:
            injection_points = list()
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
                                if isinstance(vb.getValue(), SootStaticFieldRef):
                                    field_ref = vb.getValue()
                                    if abstraction.access_path.first_field_matches(field_ref.get_field()):
                                        injection_points.append(stmt)

            if len(injection_points) > 0:
                for solver in self.solvers:
                    for stmt in injection_points:
                        solver.processEdge(PathEdge(solver.getTabulationProblem().zeroValue(), stmt, abstraction))

            return True
        return False
