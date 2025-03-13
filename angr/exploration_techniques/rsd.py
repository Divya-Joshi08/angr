from __future__ import annotations

from .base import ExplorationTechnique

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

-------------------------------------------------------------------------------------------------------------------------------------------------------------

Algorithm: (lines with an (R) are performed by the redundant state detector and 
the other lines are performed by normal symex.

DEF SYMEX: 
    construct static control dependency graph (R) 
    initialize the worklist to initial states (in angr, this is entry state?)

    while (worklist is not empty):
        pop a state S_C from worklist (constraints in angr are attached to state, so yay)

        if (S_C is at a branch with condition B):
            fork it to S_CB and S_C!B # i think this is just a figure of speech
            if (C and B) is satisfiable: # there is a prune fxn in sim_manager.py, which prunes unsat states 
                insert S_CB to worklist 
            if (C and !B) is satisfiable:
                insert S_C!B to worklist 

        else (so S_C is not at a branch):
            execute S_C # gotta assume this happens in simgr.step() but idk what even happens in that fxn
            increment S_C program counter # this is in S_C.regs, we can use S_C.regs._ip to access
            update dynamic dependency graph # i guess this can happen in step(), because it's right after execution. this means we will need to reimplement step.

-------------------------------------------------------------------------------------------------------------------------------------------------------------
'''

