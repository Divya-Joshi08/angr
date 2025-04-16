from angr import BP_BEFORE
from . import Analysis
from angr.analyses import AnalysesHub
from angr.state_plugins.sim_action import SimActionData
from angr.sim_state import SimState
import networkx as nx

class Node: #byte-level writes
    def __init__(self, addr):
        self.addr = addr
        """THings to include:
        size, teh state id, maybe if somethings symbolic"""
        
        
class DynamicDependenceGraph(Analysis):
    """I've changed the design. Instead of intercepting each write, read or
    branch before it occurs, allow step to run so all states are added in parallel
    then we can ttake advantage of history and actions to construct the graph""" 
    
    #IT MIGHT BE POSSIBLE TO HAVE BOTH CONCRETE AND SYMBOLIC, i think cases would be different
    def __init__(self, project):
        self.graph = nx.MultiDiGraph()
        super().__init__(project=project)
        
    def _on_write(state,action):
        #get the address and size
        #create the node and add it to graph
        #data dependencies
        #control dependencies
        
    def ddg_step(self, state):
        for action in state.history.recent_actions:
            if isinstance(action, SimActionData) and action.action == 'write':
                self._on_write(state, action)
                
    

        
    

        
    
    

AnalysesHub.register_default("DynamicDependenceGraph", DynamicDependenceGraph)
        