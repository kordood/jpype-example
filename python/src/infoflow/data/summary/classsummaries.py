class ClassSummaries:
    EMPTY_SUMMARIES = ImmutableClassSummaries()

    def __init__(self):
        self.summaries = dict()
        self.dependencies = list()
        self.metaData = None

    def getClassSummaries(self, className):
        return self.summaries.get( className )

    def getOrCreateClassSummaries(self, className):
        return self.summaries.setdefault( className, ClassMethodSummaries( className ) )

    def getMethodSummaries(self, className):
        cms = self.summaries.get( className )
        if cms is None:
            return None

        return cms.getMethodSummaries()

    def getAllSummaries(self):
        return self.summaries.values()

    def getAllMethodSummaries(self):
        return [v.getMethodSummaries() for v in self.summaries.values()]

    def getAllFlowsForMethod(self, signature):
        flows = set()
        for className in self.summaries.keys():
            classSummaries = self.summaries.get( className )
            if classSummaries is not None:
                methodFlows = classSummaries.getMethodSummaries().getFlowsForMethod( signature )
                if methodFlows is not None and not len( methodFlows ) != 0:
                    flows.update( methodFlows )

        return flows

    def getAllSummariesForMethod(self, signature):
        summaries = MethodSummaries()
        for className in self.summaries.keys():
            classSummaries = self.summaries.get( className )
            if classSummaries is not None:
                summaries.merge( classSummaries.getMethodSummaries().filterForMethod( signature ) )

        return summaries

    def getAllFlows(self):
        return [cs.getMethodSummaries().getAllFlows() for cs in self.summaries.values()]

    def filterForMethod(self, signature, classes=None):
        assert signature is not None

        if classes is None:
            classes = self.summaries.keys()

        newSummaries = ClassSummaries()
        for className in classes:
            methodSummaries = self.summaries.get( className )
            if methodSummaries is not None and not len( methodSummaries ) != 0:
                newSummaries.merge( methodSummaries.filterForMethod( signature ) )

        return newSummaries

    def merge(self, className, newSums):
        if newSums is None or len( newSums ) != 0:
            return

        methodSummaries = self.summaries.get( className )
        ms = newSums if isinstance(newSums, MethodSummaries) else MethodSummaries(newSums)
        if methodSummaries is None:
            methodSummaries = ClassMethodSummaries( className, ms )
            self.summaries[className] = methodSummaries
        else:
            methodSummaries.merge( ms )

    def merge(self, summaries):
        if summaries is None or len( summaries ) != 0:
            return

        for className in summaries.getClasses():
            self.merge( summaries.getClassSummaries( className ) )

        if self.metaData is not None:
            self.metaData.merge( summaries.metaData )
        else:
            metaData = SummaryMetaData( summaries.metaData )

    def merge(self, summaries):
        if summaries is None or len( summaries ) != 0:
            return False

        existingSummaries = self.summaries.get( summaries.getClassName() )
        if existingSummaries is None:
            self.summaries[summaries.getClassName()] = summaries
            return True
        else:
            return existingSummaries.merge( summaries )

    def isEmpty(self):
        return len( self.summaries ) != 0

    def getClasses(self):
        return self.summaries.keys()

    def hasSummariesForClass(self, className):
        return className in self.summaries

    def addDependency(self, className):
        if self.isPrimitiveType( className ) or className in self.summaries:
            return False
        return self.dependencies.append( className )

    def isPrimitiveType(self, typeName):
        return typeName == "int" or typeName == "long" or typeName == "float" or typeName == "double" or typeName == "char" or typeName == "byte" or typeName == "short" or typeName == "boolean"

    def clear(self):
        if self.dependencies is not None:
            self.dependencies.clear()
        if self.summaries is not None:
            self.summaries.clear()

    def validate(self):
        for className in self.summaries.keys():
            self.summaries.get( className ).validate()

    def equals(self, obj):
        if self == obj:
            return True
        if obj is None:
            return False
        other = obj
        if self.dependencies is None:
            if other.dependencies is not None:
                return False
        elif not self.dependencies == other.dependencies:
            return False
        if self.metaData is None:
            if other.metaData is not None:
                return False
        elif not self.metaData == other.metaData:
            return False
        if self.summaries is None:
            if other.summaries is not None:
                return False
        elif not self.summaries == other.summaries:
            return False
        return True
