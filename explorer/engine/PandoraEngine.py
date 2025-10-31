from angr.engines import (
    HeavyResilienceMixin,
    HeavyVEXMixin,
    HooksMixin,
    SimEngineFailure,
    SimEngineSyscall,
    SimInspectMixin,
    TrackActionsMixin,
)


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
