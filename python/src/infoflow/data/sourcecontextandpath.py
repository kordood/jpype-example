from copy import copy, deepcopy


class SourceContextAndPath:

    def __init__(self, definition, value, stmt, userData=None):
        self.path = None
        self.callStack = None
        self.neighborCounter = 0
        self.hashCode = 0
        self.definition = definition
        self.value = value
        self.stmt = stmt
        self.userData = userData

    def getPath(self):
        if self.path is None:
            return list()
    
        stmtPath = list()
        self.path.reverse()
    
        for it in self.path:
            abs = it.next()
    
            if abs.getCurrentStmt() is not None:
                stmtPath.append(abs.getCurrentStmt())
    
        return stmtPath

    def getAbstractionPath(self):
        if self.path is None:
            return None
    
        reversePath = list()
        self.path.reverse()
    
        for it in self.path:
            reversePath.add(it.next())
    
        return reversePath
    
    def extend_path(self, abs, path_config=None):
        if abs is None:
            return self
    
        if abs.getCurrentStmt() is None and abs.getCorrespondingCallSite() is None:
            return self
    
        track_path = True if path_config is None else path_config.getPathReconstructionMode().reconstructPaths()
    
        if abs.getCorrespondingCallSite() is None and not track_path:
            return self
    
        if self.path is not None:
            self.path.reverse()
            for it in self.path:
                a = it.next()
                if a == abs:
                    return None
    
        scap = None
        if track_path and abs.getCurrentStmt() is not None:
            if self.path is not None:
                top_abs = self.path[-1]
                if top_abs.equals( abs ) and top_abs.getCorrespondingCallSite() is not None \
                        and top_abs.getCorrespondingCallSite() == abs.getCorrespondingCallSite() \
                        and top_abs.getCurrentStmt() != abs.getCurrentStmt():
                    return None
    
            scap = copy(self)
    
            if scap.path is None:
                scap.path = list()
            scap.path.append( abs )
    
            if path_config is not None and 0 < len( path_config.max_path_size ) < len( scap.path ):
                return None
    
        if abs.getCorrespondingCallSite() is not None and abs.getCorrespondingCallSite() != abs.getCurrentStmt():
            if scap is None:
                scap = deepcopy(self)
            if scap.callStack is None:
                scap.callStack = list()
            elif path_config is not None and 0 < path_config.max_callstack_size() <= len( scap.callStack ):
                return None
            scap.callStack.add( abs.getCorrespondingCallSite() )
    
        self.neighborCounter = 0 if abs.getNeighbors() is None else abs.getNeighbors().size()
        return self if scap is None else scap

    def popTopCallStackItem(self):
        if self.callStack is None or self.callStack.isEmpty():
            return None

        scap = copy(self)
        lastStmt = None
        c = scap.callStack.removeLast()
        if isinstance(c, ExtensibleList):
            lastStmt = scap.callStack.getLast()
            scap.callStack = c
        else:
            lastStmt = c
    
        if scap.callStack.isEmpty():
            scap.callStack = None
        return set(scap, lastStmt)
    

    """
    def isCallStackEmpty(self):
        return self.callStack is None or self.callStack.isEmpty()
    
    
    def setNeighborCounter(self, counter):
        self.neighborCounter = counter
    
    
    def getNeighborCounter(self):
        return self.neighborCounter
    """