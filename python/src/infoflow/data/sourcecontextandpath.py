from copy import copy, deepcopy


class SourceContextAndPath:

    def __init__(self, definition, value, stmt, user_data=None):
        self.path = None
        self.call_stack = None
        self.neighbor_counter = 0
        self.hash_code = 0
        self.definition = definition
        self.value = value
        self.stmt = stmt
        self.user_data = user_data

    def get_path(self):
        if self.path is None:
            return list()
    
        stmt_path = list()
        self.path.reverse()
    
        for it in self.path:
            abstraction = it.next()
    
            if abstraction.getCurrentStmt() is not None:
                stmt_path.append(abstraction.getCurrentStmt())
    
        return stmt_path

    def get_abstraction_path(self):
        if self.path is None:
            return None
    
        reverse_path = list()
        self.path.reverse()
    
        for it in self.path:
            reverse_path.add(it.next())
    
        return reverse_path
    
    def extend_path(self, abstraction, path_config=None):
        if abstraction is None:
            return self
    
        if abstraction.getCurrentStmt() is None and abstraction.getCorrespondingCallSite() is None:
            return self
    
        track_path = True if path_config is None else path_config.getPathReconstructionMode().reconstructPaths()
    
        if abstraction.getCorrespondingCallSite() is None and not track_path:
            return self
    
        if self.path is not None:
            self.path.reverse()
            for it in self.path:
                a = it.next()
                if a == abstraction:
                    return None
    
        scap = None
        if track_path and abstraction.getCurrentStmt() is not None:
            if self.path is not None:
                top_abs = self.path[-1]
                if top_abs == abstraction and top_abs.getCorrespondingCallSite() is not None \
                        and top_abs.getCorrespondingCallSite() == abstraction.getCorrespondingCallSite() \
                        and top_abs.getCurrentStmt() != abstraction.getCurrentStmt():
                    return None
    
            scap = copy(self)
    
            if scap.path is None:
                scap.path = list()
            scap.path.append( abstraction )
    
            if path_config is not None and 0 < len( path_config.max_path_size ) < len( scap.path ):
                return None
    
        if abstraction.getCorrespondingCallSite() is not None and abstraction.getCorrespondingCallSite() != abstraction.getCurrentStmt():
            if scap is None:
                scap = deepcopy(self)
            if scap.call_stack is None:
                scap.call_stack = list()
            elif path_config is not None and 0 < path_config.max_callstack_size() <= len( scap.call_stack ):
                return None
            scap.call_stack.add( abstraction.getCorrespondingCallSite() )
    
        self.neighbor_counter = 0 if abstraction.getNeighbors() is None else abstraction.getNeighbors().size()
        return self if scap is None else scap

    def pop_top_call_stack_item(self):
        if self.call_stack is None or self.call_stack.is_empty():
            return None

        scap = copy(self)
        last_stmt = None
        c = scap.call_stack.removeLast()
        if isinstance(c, ExtensibleList):
            last_stmt = scap.call_stack.getLast()
            scap.call_stack = c
        else:
            last_stmt = c
    
        if scap.call_stack.is_empty():
            scap.call_stack = None
        return set(scap, last_stmt)
    

    """
    def isCallStackEmpty(self):
        return self.callStack is None or self.callStack.isEmpty()
    
    
    def setNeighborCounter(self, counter):
        self.neighborCounter = counter
    
    
    def getNeighborCounter(self):
        return self.neighborCounter
    """