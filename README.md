# GreedyPlasma

*WIP*

Script based on [`GreenPlasma`](https://github.com/Nightmare-Eclipse/GreenPlasma).

`green.cpp` retains the original vulnerability primitive while attempting to implement the following modifications:

* Explicit API resolution with distinct failure point isolation.
* Switched the section open mechanism to timeout-based polling to mitigate hangs.
* Logged `GrantedAccess` and map mode to capture evidence of read/write capabilities.
* Incorporated `NtMapViewOfSection` for an RW mapping attempt, gracefully degrading to an RO map upon failure.
* Reduced the default memory dump size, relying instead on a concise section fingerprint.
* Aggregated registry transition state and desktop timing metrics into the `GpRunEvidence` structure.
* Applied a hypothetical structured mutation to the ALPC path utilizing `CTF_CACHE_LAYOUT_HYPOTHESIS`.