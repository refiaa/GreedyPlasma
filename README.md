# GreedyPlasma

<img width="1266" height="676" alt="img" src="https://github.com/user-attachments/assets/bf6b646b-b3ab-44f9-8fef-399f14af1bfb" />

PoC harness for validating a Windows HKCU registry-follow primitive toward LPE.

Inspired by the original [`GreenPlasma`](https://github.com/Nightmare-Eclipse/GreenPlasma) symbolic-link direction, but this harness currently explores a different registry-follow vector.

## Current Status

Current default path: Paint HAM registry-follow primitive.

Active follow-up path: StartMenuExperienceHost HAM LU registry-follow primitive.

Observed on:

```
Windows 11 Pro 24H2
OS build 26100.2
```

```
Windows 11 Pro 25H2
OS build 26200.8037
```

Confirmed:

- Medium, non-elevated user context.
- Protected HKCU policy target rejects direct value writes and `WRITE_DAC`.
- A clean/missing Paint HAM source leaf can be staged as a `REG_LINK`.
- SYSTEM `svchost.exe` follows the staged source during the Paint lifecycle.
- Redirected target receives:

```
Mixed = REG_QWORD 0
```

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

**Source 1 (Paint HAM):**
```
HKCU\Software\Microsoft\Windows NT\CurrentVersion\HostActivityManager\CommitHistory\Microsoft.Paint_8wekyb3d8bbwe!App

```

**Source 2 (StartMenuExperienceHost HAM LU):**

```
HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\HAM\AUI\App\V1\LU

```

## About Source 2 (StartMenuExperienceHost HAM LU)

The strongest current source is:

```
HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\HAM\AUI\App\V1\LU
```

This key can be replaced with a `REG_LINK` source and triggered by restarting Explorer. Unlike the earlier Paint-only baseline, this route is not tied to launching Paint or to the Paint first-run lifecycle.

Observed with ProcMon:

- `svchost.exe` running as `NT AUTHORITY\SYSTEM` opens the staged StartMenuExperienceHost HAM LU source and receives `REPARSE`.
- When the target is `HKCU\Software\Policies\Microsoft\Windows\CloudContent`, the redirected key receives service-side value writes such as:

```
PCT = REG_QWORD
PTT = REG_QWORD
ICT = REG_QWORD
ITT = REG_QWORD
```

- When the target is `HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason`, SYSTEM service-side writes create child keys and values such as:

```
Terminator = HAM
Reason = 4
CreationTime = REG_QWORD
```

Important limitation: this is not an arbitrary registry write. The value names and data are chosen by the service-side writer.

COM LocalServer follow-up tests also reached a stronger but still non-LPE state:

- Per-user COM overrides for candidates such as `{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}` and `{5F7F3F7B-1177-4D4B-B1DB-BC6F671B8F25}` were consumed by service-side COM activation.
- ProcMon showed `svchost.exe` running as `NT AUTHORITY\SYSTEM` issuing `Process Create` for a user-controlled marker executable.
- However, the created marker process ran as the medium user, not as SYSTEM.

Therefore the current state is:

```
REG_LINK follow: confirmed
HKCU target mutation: confirmed
HKLM target mutation: partially confirmed
Service-mediated Process Create: observed
SYSTEM child process: not observed
LPE/SYSTEM shell: not achieved
```


**Tested Targets:**

* HKCU Target: `HKCU\Software\Policies\Microsoft\Windows\CloudContent`
* HKLM Target: `HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason` (Partial mutation confirmed)

> [!CAUTION]
> **LEGAL AND TECHNICAL DISCLAIMER**
>
> This code is for controlled research and analysis. The author assumes no liability for damages, system instability, or legal consequences arising from use or misuse of this software.
