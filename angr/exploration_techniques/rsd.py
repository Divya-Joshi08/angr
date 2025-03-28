from __future__ import annotations

from .base import ExplorationTechnique

class RSD(ExplorationTechnique):

    def setup(self, simgr):
        self.cfg = self.project.analyses.CFGFast() # until we figure this out, we can just use this and test on code with no calls and rets 

    def step(self, simgr, stash="active", **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)
        # i think we can use most of their step method, and there's an if stmt thats like (if something is a tuple)
        # and we add our else clause onto it 
        if len(simgr.successors) == 2:
            # we are at a branch
        else:
            hi = 1
            # update dynamic dependency graph (when do we even make this? setup? and whats the diff to static)


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

