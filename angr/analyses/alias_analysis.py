import pyvex
import logging
from angr.analyses import AnalysesHub, Analysis
from angr.analyses.reaching_definitions import ReachingDefinitionsAnalysis
from enum import Enum





_l = logging.getLogger(name=__name__)

 

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
    Really Rudimentary. Low precision :(

    """
    
    def __init__(self, func=None):
        self.cfg = self.project.analyses.CFGFast(normalize=True) #maybe i should give it the option to pass in a cfg
        self.intraprocedural_results = {}
        self.interprocedural_results = {}

        if func:
            self._intraprocedural(func)
        else:
            # 
            
    def _get_size():
        return 4
    
    def _extract_location(expr): #see if there are other test cases for other IRexpr
        if isinstance(expr, pyvex.expr.RdTmp):
            return ("tmp", expr.tmp, 0)
        elif isinstance(expr, pyvex.expr.Const):
            return ("const", expr.con.value, 0)
        elif isinstance(expr, pyvex.expr.Binop):
            if "Iop_Add" in expr.op or "Iop_Sub" in expr.op:
                args = expr.args
                if isinstance(args[0], pyvex.expr.Get) and isinstance(args[1], pyvex.expr.Const):
                    base = args[0].offset
                    offset = args[1].con.value
                    if "Sub" in expr.op:
                        offset = -offset
                    return ("reg", base, offset)
        elif isinstance(expr, pyvex.expr.Get):
            return ("reg", expr.offset, 0)
        return ("unknown", None, 0)

    
    def _parse_memory_accesses(self, irsb):
        accesses = []
        for stmt in irsb.statements:
            if isinstance(stmt, pyvex.stmt.Store):
                base_type, ident, offset = self._extract_location(stmt.addr)
                size = stmt.data.get_type_size # Not implemented apparantly :)
                accesses.append(VEXMemLocation((base_type, ident), offset, size))
            elif isinstance(stmt, pyvex.stmt.WrTmp) and isinstance(stmt.data, pyvex.expr.Load): #for a memory read, DOUBLE CHECK POR FAVOR
                base_type, ident, offset = self._extract_location(stmt.data.addr)
                size = stmt.data.get_type_size
                accesses.append(VEXMemLocation((base_type, ident), offset, size))
        return accesses
          
    def _intraprocedural(self, func):
        #stuff :)

        


AnalysesHub.register_default('AliasAnalysis', AliasAnalysis)        

   
   