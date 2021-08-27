from abstractinfoflowproblem import AbstractInfoflowProblem
from solvernormalflowfunction import SolverNormalFlowFunction
from flowfunctions import FlowFunctions
import TaintPropagationResults
import FlowFunctionType
import StaticFieldRef, ArrayRef, FieldRef, RefType, NoneType, InstanceFieldRef
import CastExpr, InstanceOfExpr
import StaticFieldTrackingMode
import TypeUtils, BooleanType, ArrayTaintType
import LengthExpr, AssignStmt, Stmt
import Collections
import Aliasing
import NewArrayExpr
import Local
import PrimType
import HashSet
import ByReferenceBoolean, BaseSelector
import KillAll

from abc import *


class InfoflowProblem(AbstractInfoflowProblem):
    def __init__(self, manager, zero_value, rule_manager_factory):
        super(InfoflowProblem, self).__init__(manager)

        self.zero_value = self.create_zero_value() if zero_value is None else zero_value
        self.results = self.TaintPropagationResults(manager)
        self.propagation_rules = rule_manager_factory.createRuleManager(manager, self.zero_value, self.results)

    def create_flow_functions_factory(self):
        return FlowFunctions()

    def auto_add_zero(self):
        return False

    def get_results(self):
        return self.results

    def get_propagation_rules(self):
        return self.propagation_rules
