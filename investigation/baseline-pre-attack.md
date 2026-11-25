# Pre-attack baseline: vm-ir-lab-01

Taken with MDE live response on 2026-11-23, before any attack step ran.
OS: Windows Server 2022, build 10.0.20348.5773.

Live response commands, from the Action center history (portal shows AEDT, UTC+11):

| UTC | AEDT | Session | Command |
|---|---|---|---|
| 03:01 | 2:01 PM | 8b6f52 | `connect` (first test) |
| 03:04 | 2:04 PM | 567c31 | `connect` |
| 03:05 | 2:05 PM | 567c31 | `processes` |
| 03:06 | 2:06 PM | 567c31 | `dir` |
| 03:07 | 2:07 PM | 567c31 | `scheduledtasks` |
| 03:08 | 2:08 PM | 567c31 | `persistence` |
| 03:12 | 2:12 PM | 567c31 | `scheduledtasks` |
| 03:22 | 2:22 PM | 74554a | `connect` |
| 03:22 | 2:22 PM | 74554a | `persistence` (`iradmin` signed in) |

Between the two sessions, the owner signed in over RDP as `iradmin` at about 03:15 UTC (2:15 PM AEDT, owner's estimate) to run `net` and `reg query` commands.
That logon and its `cmd.exe` are owner activity, not attacker activity.

Use this file to diff against the same commands after the attack.
Anything new in these lists is a lead.

## Processes

- No interactive user: `LogonUI.exe` is running, `explorer.exe` is not.
- MDE sensor healthy: `MsSense.exe`, `SenseIR.exe`, `SenseNDR.exe`, `SenseTVM.exe`,
  `MsMpEng.exe`, `MpDefenderCoreService.exe`, `DefenderAiPlatformHost.exe`, `NisSrv.exe`.
- Defender platform path: `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26100.4-0`.
- Azure agents: `WaAppAgent.exe`, `WindowsAzureGuestAgent.exe`, `WaSecAgentProv.exe`.
- Windows Update was busy at capture time: `TiWorker.exe`, `TrustedInstaller.exe`,
  `wuauclt.exe`, `MoUsoCoreWorker.exe`. Expect these again; they are not leads.
- `lsass.exe` was PID 720 on this boot. PIDs change on reboot: match on name and parent, not PID.

## C:\ root

- `C:\Temp` exists from the image (2026-10-25).
- `C:\Packages` and `C:\WindowsAzure` were created at deploy (2026-11-21).
- Nothing else outside the standard Windows folders.

## Scheduled tasks

Only two tasks sit outside `\Microsoft\Windows\`:

| Task | Runs as | Action |
|---|---|---|
| `\MicrosoftEdgeUpdateTaskMachineCore{E733DFDA-510D-49F5-95DE-5200A26BB3ED}` | SYSTEM | `C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe /c` |
| `\MicrosoftEdgeUpdateTaskMachineUA{03177888-B568-498A-9AA1-51A9DEB0859C}` | SYSTEM | `C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe /ua /installsource scheduler` |

Both are task version 1.3.319.41, registered at deploy (start boundary 2026-11-21).

Any other task outside `\Microsoft\Windows\` after the attack is new.

## Autoruns (`persistence`)

Run twice: once with no user logged in, and again with `iradmin` signed in over RDP
(03:22 UTC, session 74554a). Both runs returned the same HKLM entries and no HKCU entries,
so `persistence` does not cover HKCU here. HKCU is checked with `reg query` instead.

- Startup folders: empty.
- `HKLM\...\Run`: `SecurityHealth` (`SecurityHealthSystray.exe`) only.
- Winlogon: `Shell = explorer.exe`, `Userinit = C:\Windows\system32\userinit.exe`,
  `VmApplet = SystemPropertiesPerformance.exe /pagefile`.
- `AppInit_DLLs`: empty.
- Active Setup StubPaths: standard only (unregmp2, ie4uinit, mscories, iesetup,
  Edge 158.0.4370.33 setup).
- Shell extensions, property handlers, CLSIDs, protocol handlers: Microsoft DLLs in
  `System32` / `SysWOW64` only.

## Local accounts

From `net localgroup administrators` and `net user`, run over RDP as `iradmin`:

- Administrators group: `iradmin` only.
- Local users: `DefaultAccount`, `Guest`, `iradmin`, `WDAGUtilityAccount` (the last three are built-in).

Any new user, or any new member of Administrators, after the attack is a lead.

## HKCU autoruns (`iradmin`)

From `reg query` over RDP:

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`: key exists, no values.
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`: key does not exist.

Any value under either key after the attack, or a new `RunOnce` key, is a lead.

## Telemetry notes (advanced hunting, 2026-11-23)

- `DeviceProcessEvents` for `vm-ir-lab-01`, last 24 hours: 525 events, latest 03:39 UTC.
- Only two `reg.exe` events, both background activity, not the owner's:
  `reg.exe query hklm\software\microsoft\windows\softwareinventorylogging /v collectionstate /reg:64`,
  parent `cmd.exe`, account `system`, at 2026-11-22 23:57 UTC and 2026-11-23 02:59 UTC.
  This matches the built-in task `\Microsoft\Windows\Software Inventory Logging\Configuration`
  (`cmd.exe /d /c silcollector.cmd configure`, runs 1 minute after boot).
  Expect these again after the attack; they are not leads.
- The owner's two `reg query HKCU...` commands over RDP (about 03:15–03:25 UTC) do not
  appear in `DeviceProcessEvents`. MDE may not record every process start, so a rule
  that only matches one short-lived command can miss. Detections should not depend on
  a single process event.
- Later the same day, an interactive `reg.exe` run by `iradmin` was recorded
  (03:58:41 UTC, see the capability test below). So the gap is intermittent:
  some interactive commands are recorded and some are not.

## Custom detection capability test (2026-11-23)

Not an incident. The owner created a test rule that matches any `reg.exe` on `vm-ir-lab-*`
(Informational) to check that custom detections raise alerts on this licence.

- Scheduled run, 1-day lookback, against the two existing `reg.exe` events: no alert.
- Switched to NRT (Continuous). The owner then ran, over RDP as `iradmin`:
  `cmd.exe /d /c reg.exe query hklm\software\microsoft\windows\softwareinventorylogging /v collectionstate /reg:64`
  at 03:58:41 UTC (2:58:41 PM AEDT).
- Alert raised: incident 13, Informational, created 04:01 UTC (3:01 PM AEDT),
  about 2.5 minutes after the event. The alert's process evidence has the same time
  (03:58:41 UTC), so the alert came from this new event, not from the two older ones.
- NRT only sees events that arrive after the rule is saved.
- Follow-up test: a new scheduled rule (every 1 hour, 1-day lookback, same query,
  query checked on the rule page after saving), with no new `reg.exe` run on the VM.
  It alerted straight away on events that existed before the rule
  One alert covered all 3 events: `system` at 2026-11-22 23:57:02 UTC and 2026-11-23 02:59:44 UTC,
  and `iradmin` at 03:58:41 UTC. The alert was linked to incident 14 at 04:27:15 UTC
  (3:27:15 PM AEDT). Incident 14 also belongs to this test, not to the attack.
- So scheduled rules do pick up events from before the rule existed. The first
  scheduled run most likely did not alert because the saved rule still had the
  old HKCU filter.
- Incident 13 belongs to this test, not to the attack.
  Incidents 13 and 14 were closed as security testing, and both test rules were deleted (2026-11-23).
