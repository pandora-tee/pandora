from angr.engines import SimEngineFailure, SimEngineSyscall, HooksMixin, TrackActionsMixin, \
    SimInspectMixin, HeavyResilienceMixin, HeavyVEXMixin, TLSMixin



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
        TLSMixin,
):
    pass