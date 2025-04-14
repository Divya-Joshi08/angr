import pyvex
import logging
from angr.analyses import AnalysesHub, Analysis
from angr.analyses.reaching_definitions import ReachingDefinitionsAnalysis
from enum import Enum





_l = logging.getLogger(name=__name__)

'''
playing with reaching_defintions

'''   

class AliasType(Enum): #do you capitalize in python. lol?
    NoAlias = 0
    MayAlias = 1
    MustAlias = 2
    
class VEXMemLocation:
    """
    Represents a memory location in VEX IR.
    """
    
    def __init__(self, base, offset, size):
        self.base = base
        self.offset = offset
        self.size = size
        
    def overlaps(self, other):
        if self.base != other.base:
            return False
        selfEnd = self.offset + self.size
        otherEnd = other.offset + other.size
        return not (selfEnd <= other.offset or otherEnd <= self.offset)
    
class AliasAnalysis(Analysis):
    """
    Performs intra- and interprocedural alias analysis using angr's VEX IR.

    """
    
    def __init__(self,project, func):
        super().__init__(project=project)
        self.func = func
        self.results = {}
        self.accesses = []
        


AnalysesHub.register_default('AliasAnalysis', AliasAnalysis)        

   
   