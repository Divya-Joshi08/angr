from __future__ import annotations
import logging

from .base import ExplorationTechnique
from angr.engines.successors import SimSuccessors
from collections import defaultdict
from angr.sim_manager import SimulationManager

l = logging.getLogger(name=__name__)

class RSD(ExplorationTechnique):

    def __init__(self, cdg=None):
        super().__init__()
        self.cdg = cdg

    def setup(self, simgr):
        if (self.cdg is None):
            cfg = self.project.analyses.CFGEmulated() # i am not sure if we need to set any of the parameters 
            self.cdg = self.project.analyses.CDG(cfg)


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

            # EXECUTION HAPPENS IN THE FOLLOWING LINE
            successors = simgr.step_state(state, successor_func=successor_func, error_list=error_list, **run_args) # i said simgr.step_state but idk how simgr works as a parameter, but this is what other exp techs have done

            '''
            could put the intercept here, but im not sure if any of the below lines need to happen before we can intercept...another thing to look into later
            also just to remind myself, the successors number we want is state.step() return value, but state.step and simgr.step_state call the same factory method so i think its the right thing to use in the if stmt
            '''
            
            
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

            
            sim_succ = simgr.successors(state)
            succ_list = sim_succ.successors
            if len(succ_list) == 2:
                print("WE ARE AT A BRANCH")
                print(simgr.stashes)
            else:
                print("NOT AT BRANCH")

        simgr._clear_states(stash=stash)
        for to_stash, states in bucket.items():
            for state in states:
                if simgr._hierarchy:
                    simgr._hierarchy.add_state(state)
            simgr._store_states(to_stash or target_stash, states)

        if step_func is not None:
            return step_func(simgr)
        return simgr # I CHANGED THIS
   

    # def step(self, simgr, stash="active", **kwargs):
    #     # what i think we should do is rewrite the step method and intercept the part that gets the successors with the following if stmt:

    #     simgr = simgr.step(stash=stash, **kwargs) # this step method wont return sucessors, need to use sim_state's step method, hence the above comment
    #     # i think we can use most of their step method, and there's an if stmt thats like (if something is a tuple)
    #     # and we add our else clause onto it 
    #     if len(simgr.successors) == 2:
    #         hi=2
    #         # we are at a branch
    #     else:
    #         hi = 1
    #         # update dynamic dependency graph (when do we even make this? setup? and whats the diff to static)


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

