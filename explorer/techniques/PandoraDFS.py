import logging

from angr import ExplorationTechnique

logger = logging.getLogger(__name__)
class PandoraDFS(ExplorationTechnique):
    """
    Depth-first search. Adapted from the angr DFS

    Will only keep one path active at a time, any others will be stashed in the 'deferred' stash.
    When we run out of active paths to step, we take the first from deferred.
    """

    def __init__(self, deferred_stash="deferred"):
        super().__init__()
        self.deferred_stash = deferred_stash

    def setup(self, simgr):
        if self.deferred_stash not in simgr.stashes:
            simgr.stashes[self.deferred_stash] = []

    def step(self, simgr, stash="active", **kwargs):

        simgr = simgr.step(stash=stash, **kwargs)

        if len(simgr.stashes[stash]) > 1:
            simgr.split(from_stash=stash, to_stash=self.deferred_stash, limit=1)

        if len(simgr.stashes[stash]) == 0 and len(simgr.stashes[self.deferred_stash]) != 0:
            # Active ran out of states. Repopulate from deferred stash if it is not empty
            simgr.stashes[stash].append(simgr.stashes[self.deferred_stash].pop(0)) # Pop first item

        return simgr
