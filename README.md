# GreedyPlasma

Script based on [`GreenPlasma`](https://github.com/Nightmare-Eclipse/GreenPlasma).

This repository is a PoC-oriented harness for original GreenPlasma primitive. 

## Objectives

* The session object-manager link and trigger path can lead to a section handle for the target object.
* The Cloud Files policy path `HKCU\Software\Policies\Microsoft\CloudFiles\BlockedApps` can be recreated as a registry symbolic link.
* That registry link can be pointed at `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System`.
* A controlled HKCU policy value write can be demonstrated through that path.
* The default demonstration payload is `DisableLockWorkstation=1`.

In short, this harness can demonstrate a controlled HKCU registry-write primitive in the original GreenPlasma direction. 

## Evidence To Look For

A successful run for the original primitive should include logs like:

```text
link=ok
trigger=ok
section=ok
reglink target=\REGISTRY\USER\...\Software\Microsoft\Windows\CurrentVersion\Policies\System
reg_link_touch=ok ...
reg_value=ok target=Software\Microsoft\Windows\CurrentVersion\Policies\System value=DisableLockWorkstation
registry=ok
```

`lock=ok` and `desktop=lost phase=post-lock ...` are useful effect/timing evidence, but the core registry-write evidence is the `reglink`, `reg_link_touch`, `reg_value=ok`, and `registry=ok` sequence.

## Observed Test Environment

The registry-write primitive described above was observed in:

```text
Edition: Windows 11 Pro
Version: 25H2
Installed on: 5/15/2026
OS build: 26200.8037
Experience: Windows Feature Experience Pack 1000.26100.300.0
```

Other Windows builds, VM products, user profiles, policy states, and session conditions may produce different results.

## Section And ALPC Notes

The current diagnostics have shown cases where the observed section is:

```text
\BaseNamedObjects\CTFMON_DEAD
```

with access like:

```text
query=1 read=1 write=0 dac=0 owner=0
```

and security descriptors granting read/query-style access but not `SECTION_MAP_WRITE`. In that state, `NtMapViewOfSection` can only produce a read-only mapping, so the `GP_CACHE_LAYOUT_HYPOTHESIS` ALPC mutation path remains In that state, `NtMapViewOfSection` can only produce a read-only mapping, so the `GP_CACHE_LAYOUT_HYPOTHESIS` ALPC mutation path remains an unproven experiment rather than part of the proven primitive.

The ALPC, token, shell, DLL, and direct code paths are kept as explicit status-oriented boundaries. 

## Difference From The Original PoC

This harness keeps the original direction but adds:

* Explicit native API resolution checks.
* Timeout-based section polling instead of an infinite wait.
* Per-step registry logs for DACL changes, symbolic link creation, target touch, and value write.
* Section access, map mode, fingerprint, object name/type, and SDDL diagnostics.
* Desktop timing logs before later precondition checks.
* Cleanup scoped to keys/values created or touched by this run where possible.
* Clear separation between the proven registry-write primitive and unproven follow-on hypotheses.

## Development Status

The registry primitive has been made observable. The broader ALPC/token/code-execution ideas remain experimental and should be documented as unproven unless separate evidence is produced.

> [!CAUTION]
> **LEGAL AND TECHNICAL DISCLAIMER**
>
> This code is for controlled research and analysis. The author assumes no liability for damages, system instability, or legal consequences arising from use or misuse of this software.
