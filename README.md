# GreedyPlasma

still working on it.

Script based on [`GreenPlasma`](https://github.com/Nightmare-Eclipse/GreenPlasma).

`green.cpp` retains the original vulnerability primitive while attempting to make the flow more observable and less dependent on hard stops. The code should be read as an experimental PoC-oriented harness, not as a guaranteed end-to-end exploit chain.

## What this fork is trying to exercise

At a high level, the code attempts to:

* Resolve the required native APIs explicitly and report distinct failure points.
* Create the session object-manager link used by the original primitive.
* Trigger the target-side section creation path and wait for the resulting section through timeout-based polling.
* Capture section evidence, including granted access, map mode, a compact prefix dump, and a small fingerprint.
* Attempt an `NtMapViewOfSection` mapping with graceful fallback from RW to RO where possible.
* Track registry transition state and desktop timing metrics through `GpRunEvidence`.
* Apply a hypothetical structured mutation to an ALPC path field using `GP_CACHE_LAYOUT_HYPOTHESIS`.
* Route the later sink checks through one shared flow so that ALPC capture, shell launch, DLL load, and direct code execution attempts are not isolated placeholder calls.

## Current sink surface

The sink layer is intentionally status-oriented. Each sink returns a `GpBlockedSinkResult` with an implementation flag, a precondition status, and a short reason string.

The current code can attempt the following, depending on runtime preconditions and requested options:

* ALPC token capture through a spoofed server port.
* A process launch through `CreateProcessAsUserW` using a captured primary token.
* A DLL load attempt through `rundll32.exe` using the captured token.
* A direct in-process entry point call while impersonating the captured token.

These paths are conditional. They depend on the section mutation being meaningful for the actual target-side layout, the ALPC client connecting within the timeout window, the captured token being usable in the current session, and Windows policy/security state allowing the follow-on operation.

## What this does not prove

This fork does not claim that the full chain will succeed on every system. In particular:

* `GP_CACHE_LAYOUT_HYPOTHESIS` is still a hypothesis, not a verified schema.
* Desktop timing is used as an observation signal, not as proof that the target consumed the mutated state.
* ALPC capture depends on runtime message flow and impersonation rights.
* The DLL path uses a `rundll32.exe` style invocation, so the requested DLL must expose a compatible entry point for that path to be meaningful.
* Direct code execution requires a valid executable address in the current process and does not make broad safety guarantees about the called function.

## Modifications from the original direction

Compared with the base PoC direction, this version currently adds or changes:

* Explicit API resolution with distinct failure point isolation.
* Timeout-based section polling to mitigate hangs.
* Logged `GrantedAccess` and map mode to capture evidence of read/write capabilities.
* `NtMapViewOfSection`-based mapping with RW-to-RO fallback.
* A reduced default memory dump size backed by a concise section fingerprint.
* Aggregated registry, desktop, mapping, ALPC, and sink state in `GpRunEvidence`.
* Configurable sink requests through parsed command-line options rather than hard-coded placeholder calls.
* Shared precondition handling for token-backed sinks.

## Development status

The code is still WIP. The current intent is to make the flow easier to inspect statically and easier to reason about when run in a controlled research environment, while keeping failure states explicit rather than silently assuming success.

> [!CAUTION]
> LEGAL AND TECHNICAL DISCLAIMER
> The author assumes no liability for any damages, system instability, or legal consequences arising from the use of this software. 
