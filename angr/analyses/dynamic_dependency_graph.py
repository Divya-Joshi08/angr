from . import Analysis
from angr.analyses import AnalysesHub
from angr.state_plugins.sim_action import SimActionData
from angr.state_plugins.scratch import SimStateScratch
from angr.state_plugins.history import SimStateHistory
from collections import defaultdict
from angr.sim_state import SimState
import networkx as nx

#possibly helpful plugins scratch, history, hierarchy
#scratch looks like it could be especilaly helpgul
class Node: #byte-level writes
    def __init__(self, addr, state: SimState, size, data, id):
        self.addr = addr #object
        self.state = state #kinda bulky, might not be needed
        self.size = size #object
        self.data = data #object
        self.id = id

        
        
class DynamicDependenceGraph(Analysis):
    """I've changed the design. Instead of intercepting each write, read or
    branch before it occurs, allow step to run so all states are added in parallel
    then we can ttake advantage of history and actions to construct the graph""" 
    
    #IT MIGHT BE POSSIBLE TO HAVE BOTH CONCRETE AND SYMBOLIC, i think cases would be different
    def __init__(self, project):
        self.graph = nx.MultiDiGraph()
        super().__init__(project=project)
        self.last_write_addr = defaultdict(list)
        self.id_to_node = defaultdict(list)
        self.node_counter = 0
        
    def _on_write(self,state, action):
        if action.type != 'mem': #do i need to care about register writes
            return
        
        #get the address and size
        addr = action.addr #actual_addr if concrete maybe, but its aalways set to none so idk
        size = action.size
        data = action.data
        
        
        #create the node and add it to graph
        node = Node(addr, state, size, data, self.node_counter)
        self.id_to_node[self.node_counter].append(node)
        self.node_counter += 1
        self.graph.add_node(node)
        self.last_write_addr[addr].append(node)
        
        
        #data dependencies
            #check to see if any variables are in ast
        if hasattr(data, 'variables'):
            for(addr, write) in self.last_write_addr.items():
                for w in write:
                    if w.data is not None and any(v in data.variables for v in w.data.variables):
                        self.graph.add_edge(w.id, data.id, type='DATA')
        
        
        #control dependencies
            #look at the branch history of the state and do the same thing as with data
            #tracking the branch history is the hard part
            
        #potential
    
    #right now we would manually call this during our step, wed want to do it for 
    #all the states in the active stash , might be a better way to do this idk    
    def ddg_step(self, state):
        for action in state.history.recent_actions:
            if isinstance(action, SimActionData) and action.action == 'write':
                self._on_write(state, action)
                
    

        
    

        
    
    

AnalysesHub.register_default("DynamicDependenceGraph", DynamicDependenceGraph)
        