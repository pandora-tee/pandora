from angr.engines import SimEngineFailure, SimEngineSyscall, HooksMixin, TrackActionsMixin, \
    SimInspectMixin, HeavyResilienceMixin, HeavyVEXMixin



class PandoraEngine(
        SimEngineFailure,
        SimEngineSyscall,
        HooksMixin,
        # SimEngineUnicorn, # We do not use unicorn
        # SuperFastpathMixin,  # We probably don't need that?
        TrackActionsMixin,
        SimInspectMixin,
        HeavyResilienceMixin,
        # SootMixin, # For Java
        HeavyVEXMixin,
):
    pass