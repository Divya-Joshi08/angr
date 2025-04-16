from angr.state_plugins.sim_action import SimActionExit
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
    then we can take advantage of history and actions to construct the graph""" 
    
    #IT MIGHT BE POSSIBLE TO HAVE BOTH CONCRETE AND SYMBOLIC, i think cases would be different
    def __init__(self, project):
        self.graph = nx.MultiDiGraph()
        super().__init__(project=project)
        self.last_write_addr = defaultdict(list)
        self.id_to_node = defaultdict(list)
        self.branch_history = defaultdict(list)
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
                        self.graph.add_edge(w.id, node.id, type='DATA')
        
        
        #control dependencies
            #look at the branch history of the state and do the same thing as with data
            #tracking the branch history is the hard part
        for cond, influencing_writes in self.branch_history:
            if hasattr(cond, 'variables') and any(v in data.variables for v in cond.variables):
                 for w in influencing_writes:
                    self.graph.add_edge(w.id, node.id, type='CONTROL')
            
            
        #potential
        #this might kill me :) goodnight
    
    def _check_branch(self, action):
        # last_jmp = state.history.jumpkind
        # if last_jmp == 'Ijk_Boring':
        #     cond_ins = state.history.jump_source #looks like it is state.scratch.exit_ins_addr set in successsors.py
        influencing_writes = [] #need to get the variables read
        cond = action.condition
        if hasattr(cond, 'variables'):
                for (addr, writes) in self.last_write_addr.items():
                    for w in writes:
                        if w.data is not None and any(v in cond.variables for v in w.data.variables):
                            influencing_writes.append(w)
        self.branch_history.append((cond, influencing_writes))   
        #idk what all the clone nonsense is all about MOVE FAST BREAK THINGS AHAHHAHAHAH T-T
        
    #right now we would manually call this during our step, wed want to do it for 
    #all the states in the active stash , might be a better way to do this idk    
    def ddg_step(self, state):
        #self._check_branch(state)
        for action in state.history.recent_actions:
            if isinstance(action, SimActionData) and action.action == 'write':
                self._on_write(state, action)
            if isinstance(action, SimActionExit) and action.exit_type == SimActionExit.CONDITIONAL: #im not sure this is what i think it is
                self._check_branch(action)
                

AnalysesHub.register_default("DynamicDependenceGraph", DynamicDependenceGraph)
        