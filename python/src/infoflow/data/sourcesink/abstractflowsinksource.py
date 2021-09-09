class AbstractFlowSinkSource:

    def __init__(self, type, parameterIdx, baseType, accessPath=None, gap=None, userData=None, matchStrict=None):
        self.type = type
        self.parameterIdx = parameterIdx
        self.baseType = baseType
        self.accessPath = accessPath
        self.gap = gap
        self.userData = userData
        self.matchStrict = matchStrict

    def isCoarserThan(self, other):
        if self.equals( other ):
            return True

        if self.type != other.type or self.parameterIdx != other.parameterId or not safeCompare( self.baseType,
                                                                                                 other.baseType ) or not safeCompare(
                self.gap, other.gap ):
            return False
        if self.accessPath is not None and other.accessPath is not None:
            if self.accessPath.length() > other.accessPath.length():
                return False
            for i in range( 0, len( self.accessPath ) ):
                if not self.accessPath.getField( i ).equals( other.accessPath.getField( i ) ):
                    return False

        return True

    def isParameter(self):
        return self.type == SourceSinkType.Parameter

    def isThis(self):
        return self.type == SourceSinkType.Field and not hasAccessPath()

    def isCustom(self):
        return self.type == SourceSinkType.Custom

    def isField(self):
        return self.type == SourceSinkType.Field

    def isReturn(self):
        return self.type == SourceSinkType.Return

    def isGapBaseObject(self):
        return self.type == SourceSinkType.GapBaseObject

    def hasAccessPath(self):
        return accessPath is not None and not accessPath.isEmpty()

    def getAccessPathLength(self):
        return accessPath is None ? 0: accessPath.length()

    def hasGap(self):
        return self.gap is not None

    def getLastFieldType(self):
        if accessPath is None or accessPath.isEmpty():
            return self.baseType
        return accessPath.getLastFieldType()

    def isMatchStrict(self):
        return matchStrict

    def equals(self, obj):
        if self == obj:
            return True
        if obj is None:
            return False
        other = obj
        if accessPath is None:
            if other.accessPath is not None:
                return False
        elif not accessPath.equals( other.accessPath ):
            return False
        if self.baseType is None:
            if other.baseType is not None:
                return False
        elif not self.baseType.equals( other.baseType ):
            return False
        if gap is None:
            if other.gap is not None:
                return False
        elif not gap.equals( other.gap ):
            return False
        if matchStrict != other.matchStrict:
            return False
        if parameterIdx != other.parameterIdx:
            return False
        if type != other.type:
            return False
        if userData is None:
            if other.userData is not None:
                return False
        elif not userData.equals( other.userData ):
            return False
        return True

    def safeCompare(self, o1, o2):
        if o1 is None:
            return o2 is None
        if o2 is None:
            return o1 is None
        return o1.equals( o2 )

    def xmlAttributes(self):
        res = dict()
        if isParameter():
            res.put( XMLConstants.ATTRIBUTE_FLOWTYPE, XMLConstants.VALUE_PARAMETER )
            res.put( XMLConstants.ATTRIBUTE_PARAMTER_INDEX, getParameterIndex() + "" )
        elif isField():
            res.put( XMLConstants.ATTRIBUTE_FLOWTYPE, XMLConstants.VALUE_FIELD )
        elif isReturn():
            res.put( XMLConstants.ATTRIBUTE_FLOWTYPE, XMLConstants.VALUE_RETURN )
        else:
            raise RuntimeError( "Invalid source type" )

        if self.baseType is not None:
            res.put( XMLConstants.ATTRIBUTE_BASETYPE, baseType )
        if hasAccessPath():
            res.put( XMLConstants.ATTRIBUTE_ACCESSPATH, getAccessPath().toString() )
        if gap is not None:
            res.put( XMLConstants.ATTRIBUTE_GAP, getGap().getID() + "" )

        return res

    def replaceGaps(self, replacementMap):
        pass


