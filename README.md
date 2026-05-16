# GreedyPlasma

<img width="1266" height="676" alt="img" src="https://github.com/user-attachments/assets/bf6b646b-b3ab-44f9-8fef-399f14af1bfb" />

PoC harness for validating a Windows HKCU registry-follow primitive toward LPE.

Based on the original [`GreenPlasma`](https://github.com/Nightmare-Eclipse/GreenPlasma) direction.

## Current Status

Current default path: Paint HAM registry-follow primitive.

Observed on:

> Windows 11 24H2
>
> OS build 26100.2

Confirmed:

- Medium, non-elevated user context.
- Protected HKCU policy target rejects direct value writes and `WRITE_DAC`.
- A clean/missing Paint HAM source leaf can be staged as a `REG_LINK`.
- SYSTEM `svchost.exe` follows the staged source during the Paint lifecycle.
- Redirected target receives:

> Mixed = REG_QWORD 0

Current claim:


**target-mutated-unattributed**


Not yet proven:

- `lpe-observed`
- SYSTEM shell
- Arbitrary registry write
- DACL control
- Token capture
- DLL/code execution

## Default Source And Target

Source:

> HKCU\Software\Microsoft\Windows NT\CurrentVersion\HostActivityManager\CommitHistory\Microsoft.Paint_8wekyb3d8bbwe!App

Default target:

> HKCU\Software\Policies\Microsoft\Windows\CloudContent

> [!CAUTION]
> **LEGAL AND TECHNICAL DISCLAIMER**
>
> This code is for controlled research and analysis. The author assumes no liability for damages, system instability, or legal consequences arising from use or misuse of this software.
