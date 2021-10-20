from .reachablemethods import ReachableMethods


class Scene:

    @staticmethod
    def get_reachable_methods(callgraph, entrypoints):
        reachable_methods = ReachableMethods(callgraph, entrypoints)
        reachable_methods.update()
        return reachable_methods
