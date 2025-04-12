from __future__ import annotations
import logging
import claripy

from .base import ExplorationTechnique
from angr.engines.successors import SimSuccessors
from collections import defaultdict
from angr.sim_manager import SimulationManager
from angr.knowledge_plugins.cfg import CFGENode

l = logging.getLogger(name=__name__)

class RSD(ExplorationTechnique):

    def __init__(self, cdg=None, covered_lines=None, relevant_branches=None):
        super().__init__()
        self.cdg = cdg
        self.covered_lines = covered_lines
        self.relevant_branches = relevant_branches

    def setup(self, simgr):
        # static control dependency graph
        if (self.cdg is None):
            self.cfg = self.project.analyses.CFGEmulated(keep_state=True) # i am not sure if we need to set any of the parameters 
            self.cdg = self.project.analyses.CDG(self.cfg)
        
        # create relevant branches set (basically all branches)
        self.relevant_branches = set()
        for node in list(self.cfg.graph.nodes):
            if node.simprocedure_name != 'PathTerminator':
                state = node.input_state
                succ = simgr.successors(state)
                succlist = succ.successors
                if len(succlist) > 1:
                    self.relevant_branches.add(state.regs._ip)
        
        # map from addresses to nodes, so that we can get the node to look in the CDG
        self.nodemap = dict()
        for node in list(self.cdg._graph.nodes()):
            self.nodemap[node.addr] = node
        
        # set to check if a line is covered 
        if (self.covered_lines is None):
            self.covered_lines = set()


    def step(
        self,
        simgr,
        stash="active",
        target_stash=None,
        n=None,
        selector_func=None,
        step_func=None,
        error_list=None,
        successor_func=None,
        until=None,
        filter_func=None,
        **run_args,
    ):
        """
        Step a stash of states forward and categorize the successors appropriately.

        The parameters to this function allow you to control everything about the stepping and
        categorization process.

        :param stash:           The name of the stash to step (default: 'active')
        :param target_stash:    The name of the stash to put the results in (default: same as ``stash``)
        :param error_list:      The list to put ErrorRecord objects in (default: ``self.errored``)
        :param selector_func:   If provided, should be a function that takes a state and returns a
                                boolean. If True, the state will be stepped. Otherwise, it will be
                                kept as-is.
        :param step_func:       If provided, should be a function that takes a SimulationManager and
                                returns a SimulationManager. Will be called with the SimulationManager
                                at every step. Note that this function should not actually perform any
                                stepping - it is meant to be a maintenance function called after each step.
        :param successor_func:  If provided, should be a function that takes a state and return its successors.
                                Otherwise, project.factory.successors will be used.
        :param filter_func:     If provided, should be a function that takes a state and return the name
                                of the stash, to which the state should be moved.
        :param until:           (DEPRECATED) If provided, should be a function that takes a SimulationManager and
                                returns True or False. Stepping will terminate when it is True.
        :param n:               (DEPRECATED) The number of times to step (default: 1 if "until" is not provided)

        Additionally, you can pass in any of the following keyword args for project.factory.successors:

        :param jumpkind:        The jumpkind of the previous exit
        :param addr:            An address to execute at instead of the state's ip.
        :param stmt_whitelist:  A list of stmt indexes to which to confine execution.
        :param last_stmt:       A statement index at which to stop execution.
        :param thumb:           Whether the block should be lifted in ARM's THUMB mode.
        :param backup_state:    A state to read bytes from instead of using project memory.
        :param opt_level:       The VEX optimization level to use.
        :param insn_bytes:      A string of bytes to use for the block instead of the project.
        :param size:            The maximum size of the block, in bytes.
        :param num_inst:        The maximum number of instructions.
        :param traceflags:      traceflags to be passed to VEX. Default: 0

        :returns:           The simulation manager, for chaining.
        :rtype:             SimulationManager
        """
        l.info("Stepping %s of %s", stash, simgr)
        # I REMOVED THE COMPATIBILITY LAYER - DONT THINK ITS NEEDED, BUT WILL LOOK MORE
        bucket = defaultdict(list)
        target_stash = target_stash or stash
        error_list = error_list if error_list is not None else simgr._errored

        for state in simgr._fetch_states(stash=stash):
            goto = simgr.filter(state, filter_func=filter_func)
            if isinstance(goto, tuple):
                goto, state = goto

            if goto not in (None, stash):
                bucket[goto].append(state)
                continue

            if not simgr.selector(state, selector_func=selector_func):
                bucket[stash].append(state)
                continue

            pre_errored = len(error_list)

            # self.covered_lines.add(state.regs._ip) # add the program counter to covered lines
            # EXECUTION HAPPENS IN THE FOLLOWING LINE
            successors = simgr.step_state(state, successor_func=successor_func, error_list=error_list, **run_args) # i said simgr.step_state but idk how simgr works as a parameter, but this is what other exp techs have done
            
            # ---------------------------------------handle degenerate stepping cases here. desired behavior: ------------------------------------------
            # if a step produced only unsat states, always add them to the unsat stash since this usually indicates bugs
            # if a step produced sat states and save_unsat is False, drop the unsats
            # if a step produced no successors, period, add the original state to deadended

            # first check if anything happened besides unsat. that gates all this behavior
            if not any(v for k, v in successors.items() if k != "unsat") and len(error_list) == pre_errored:
                # then check if there were some unsats
                if successors.get("unsat", []):
                    # only unsats. current setup is acceptable. Q: what if there are SOME unsats??
                    pass
                else:
                    # no unsats. we've deadended.
                    bucket["deadended"].append(state)
                    continue
            else:
                # there were sat states. it's okay to drop the unsat ones if the user said so.
                if not simgr._save_unsat:
                    successors.pop("unsat", None)

            for to_stash, successor_states in successors.items():
                bucket[to_stash or target_stash].extend(successor_states)

            # ----------------------------------------INTERCEPT IS HERE--------------------------------------------
            sim_succ = simgr.successors(state)

            # add program counters to the covered lines set
            succ_list = sim_succ.successors
            if len(succ_list) == 2:
                print("WE ARE AT A BRANCH")
                print(simgr.stashes)
            else:
                print("NOT AT BRANCH", str(state.regs._ip))
                #TODO update dynamic dependency graph
                if (state.regs._ip not in self.covered_lines):
                    print("reached an uncovered line")
                    line = state.regs._ip
                    self.covered_lines.add(line)

                    #TODO update relevant static branches:
                    if (state.solver.eval(line) in self.nodemap): # this means it is directly dependent on control instruction, if its not it will get covered anyway
                        newline_node = self.nodemap[state.solver.eval(line)]
                        self.update_relevant_static_branches(newline_node)
                    #TODO refine relevant location sets
                
                #TODO find match

                '''
                if (state has match or is at exit):
                    #TODO construct relevant location sets 
                '''
            #----------------------------------THIS IS WHERE OUR CODE ENDS-------------------------------------------

        simgr._clear_states(stash=stash)
        for to_stash, states in bucket.items():
            for state in states:
                if simgr._hierarchy:
                    simgr._hierarchy.add_state(state)
            simgr._store_states(to_stash or target_stash, states)

        if step_func is not None:
            return step_func(simgr)
        return simgr # I CHANGED THIS
    
    def update_relevant_static_branches(self, node):
        print("updating relevant static branches")
        # so we just marked something covered 
        # it could affect all parent branches
        # so look at its parent. if this was the last uncovered branch of that parent, then the parent is no longer relevant.
        # ONLY IF we mark the parent irrelevant, the next parent could be irrelevant
        print("node:"+str(node))
        queue = [] # of nodes to check
        # for parent in self.cdg.get_guardians(node):
        #     # print("parent: "+str(parent))
        #     if claripy.BVV(parent.addr, 64) in self.relevant_branches:
        #         # print("appending"+str(parent))
        #         queue.append(parent)
        # if len(queue) > 0:
        #     print(queue)

        queue.append(node)

        while len(queue) > 0:
            node = queue.pop(0)
            for parent in self.cdg.get_guardians(node):
                if claripy.BVV(parent.addr, 64) in self.relevant_branches:
                    relevant = False
                    for child in self.cdg.get_dependants(parent):
                        addr = claripy.BVV(child.addr, 64)
                        if (addr in self.relevant_branches) or (addr not in self.covered_lines):
                            relevant = True 
                            break
                    if not relevant:
                        self.relevant_branches.remove(claripy.BVV(parent.addr, 64)) 
                        queue.append(parent)
        print("relevant branches", self.relevant_branches)

        '''
        while (irrelevant guardians queue is nonempty):
            pop a guardian
            for each RELEVANT guardian:
                relevant is false (for now)
                for each child of this guardian:
                    if it is a relevant branch or an uncovered line:
                        relevant is true, break
                if relevant is false:
                    mark this guardian irrelevant
                    add it to the queue
        '''
   


''' hiiiii
class RSD(ExplorationTechnique):

setup():
    make the static control dependence graph

step():
    i think we can use their implementation

selector():
    maybe we can use this to not step redundant states ? 

Questions:
- when is the dynamic control dependence graph constructed?
- would relevant locations be registers/memory locations?

-------------------------------------------------------------------------------------------------------------------------------------------------------------

Algorithm: (lines with an (R) are performed by the redundant state detector and 
the other lines are performed by normal symex.

DEF SYMEX: 
    construct static control dependency graph (R) 
    initialize the worklist to initial states (in angr, this is entry state?)

    while (worklist is not empty):
        pop a state S_C from worklist (constraints in angr are attached to state, so yay)

        if (S_C is at a branch with condition B): # preeetttyyy sure this is all taken care of by simgr.step() :p (?)
            fork it to S_CB and S_C!B # i think this is just a figure of speech
            if (C and B) is satisfiable: # there is a prune fxn in sim_manager.py, which prunes unsat states 
                insert S_CB to worklist 
            if (C and !B) is satisfiable:
                insert S_C!B to worklist 

        else (so S_C is not at a branch):
            execute S_C # gotta assume this happens in simgr.step() but idk what even happens in that fxn
            increment S_C program counter # this is in S_C.regs, we can use S_C.regs._ip to access
            update dynamic dependency graph # i guess this can happen in step(), because it's right after execution. this means we will need to reimplement step

            if (S_C was previously uncovered) # i guess we can have a data structure for this, can also happen in step()?
                update relevant static branches using static graph # relevant means there is path from branch to a uncovered line, also step()?
                update relevant location sets # each state has a rel loc set, and since we got to uncovered line, we remove vars that control that line, 
                  -  maybe we can add relevant locations as a state attribute, that might cause a lot of drama though
            
            find match # search for relevant constraint set that implies this state (maybe put in prune? but idk if prune comes after step like we want it to)

            if (state has match or is at program exit):
                construct relevant location sets # yep this is when that's done
                compute test inputs and delete the state
            else:
                add the state to the worklist
            

-------------------------------------------------------------------------------------------------------------------------------------------------------------

Notes:
- a state is redundant if relevant constraints for a snapshot IMPLY relevant constraints for that state 
(relvant constraints are constraints on relevant locations/variables)
(relevant locations are the ones that affect relevant static branches further down, this is why relevant location sets for the state are only constructed when the state reaches an exit - uhhh there's something confusing about this)

static control dependence graph
- 
'''

