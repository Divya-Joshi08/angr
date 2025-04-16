from angr import BP_BEFORE
from . import Analysis
from angr.analyses import AnalysesHub
from angr.sim_state import SimState
import networkx as nx

class Node: #byte-level writes
    def __init__(self, addr):
        self.addr = addr
        
        
class DynamicDependenceGraph(Analysis): 
    #Remember to add hooks to memeory so that this gets changed dynamically
    def __init__(self):
        self.graph = nx.MultiDiGraph()
        entry_state = self.project.factory.entry_state()
        self._hook_state(entry_state)
    
    def _hook_state(self, state):
        state.inspect.b('mem_write', when=BP_BEFORE, action=self._on_write(state))#does before or after matter
        #prob need to add reads and branches
        
    def _add_dependency(self, src, dst, type):
        self.graph.add_edge(src, dst, type=type) #I think this is the attribute, not sure
    
    def _on_write(self, state):
        #get where the write is occuring and what is being written(what is being written might not be necessary im not sure)
        
        #different case base on fi addresses are symbolic or concrete, remember to do the same check in aliasing
        
        #create a node for the graph and add it to the graph(each write is unique)
        
        #find data dependencies
            #find memory reads from the state tos ee if write is using a value that was read before
            
        #find control dependencies
        
        #find potential dependencies

        
    
    

AnalysesHub.register_default("DynamicDependenceGraph", DynamicDependenceGraph)
        