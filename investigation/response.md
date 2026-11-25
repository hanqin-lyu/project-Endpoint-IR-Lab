# Phase 6: response (checklist and record)

The owner runs every step in the Defender portal or on the VM. This file is the
checklist and the record. Times are UTC. Every `[placeholder]` is filled from the real
run; nothing here is a result until then.

Order: preserve → test the 06:07 point → release the user → indicator → cleanup →
verify. The indicator goes before cleanup so its "remediate" half has existing copies to
remove, which is the proof that it works.

## Record

| # | Step | Started (UTC) | Done (UTC) | Result | Evidence |
|---|------|---------------|------------|--------|----------|
| 0 | Disk snapshot (`preserve-disk.md`) | 07:21:26 (2026-11-25) | 07:22:11 | Succeeded, incremental | `snap-ir-lab-01-evidence-20261125T072126Z` |
| 1 | Re-test RDP while contained | 07:25:31 | About 07:26 (signed out at once; no logoff event) | Allowed, not blocked or logged by containment | `DeviceLogonEvents` export (kept outside the repo: SID, IP, DeviceId) |
| 2 | Release `iradmin` containment | 08:00:45 | 08:00 | Uncontained, Completed | Incident Activities "uncontained" row; Action center History "Release user containment", approval ID 26e9ef |
| 3 | Custom indicator, block and remediate | about 08:15 | about 08:15 | Created; SHA256 and Expires Never confirmed on the detail panel; action Block and remediate (owner confirmed) | Indicator detail panel (owner's screenshot, shows email) |
| 4 | Remediation of existing copies | 09:15 | 09:28:34 | Not removed while untouched (09:15 check); read blocked and quarantined on first access (09:28:18 → 09:28:34) | `Get-MpThreatDetection` output; query CSV |
| 5 | Re-execution blocked | 09:35:38 | 09:38:33 | Restored copy ran (exempted by the restore); a fresh copy with the same hash was blocked at run time | PowerShell output, Windows Security "Content is blocked"; two Custom TI alerts; query CSV |
| 6 | Remove `\spawn` | 10:00:06 | 10:00:41 | Removed (`remediate` Completed); `schtasks /query /tn spawn` finds nothing | Live response command log |
| 7 | Remove `T1136.001_Admin` | 10:02:38 | 10:02:47 | Removed; it was enabled; no profile folder | PowerShell output |
| 8 | Remove `C:\lab` | 10:03:01 | 10:03:10 (with step 9) | Removed (12 items, incl. `restore\stub.exe`) | PowerShell output |
| 9 | Remove `C:\AtomicRedTeam` | 10:03:01 | 10:03:10 (with step 8) | Removed | PowerShell output |
| 10 | Verify cleanup in advanced hunting | after 10:03 | – | Account and file deletions logged; no `ScheduledTaskDeleted` | Query CSV (counts only) |

ServiceNow ticket: add a work note at each step. [ticket number]

## 0. Preserve the disk

Cleanup destroys on-disk evidence. If `preserve-disk.md` has not been run yet, run it
now, before step 6.

It had not been run. Taken on 2026-11-25, before any phase 6 change on the VM:

| Field | Value |
|-------|-------|
| Name | `snap-ir-lab-01-evidence-20261125T072126Z` |
| Source | OS disk of `vm-ir-lab-01` (resource group `rg-endpoint-ir-lab`) |
| Type | Incremental |
| VM state at snapshot | Stopped. The VM booted at 07:24:29 UTC (`lsass.exe` creation time in step 1), two minutes after the snapshot |
| Created (Azure `timeCreated`) | 2026-11-25 07:22:11 UTC |
| State | Succeeded |

The snapshot is about a day after the attack (2026-11-24), so the disk also holds later
activity, including the owner's live response work. The snapshot must be
deleted by hand at the end of the project (`preserve-disk.md`, Cleanup).

## 1. The 06:07 point: re-test while still contained

Open question: attack disruption contained `iradmin` at 05:58:59, logged off RDP
session 2 at 06:06:35, and the policy still shows Active, yet `iradmin` signed in again
over RDP at 06:07:24 (Network logon 06:07:23, RemoteInteractive 06:07:24) and ran step
4 again. `DisruptionAndResponseEvents` has no `ContainedUserLogonBlocked` at or after
06:07. Microsoft's documentation says a contained user's incoming RDP, SMB, RPC and
network logons are blocked on onboarded devices.

The test runs before step 2, while the policy is still Active:

1. Check the policy status: incident 15 → Activities → "iradmin contained" → Policy
   status. Active (checked after the test).
2. From the same Mac as at 06:07, open an RDP session to `vm-ir-lab-01` as `iradmin`.
   Note the time and what the client shows. 07:25 UTC, allowed.
3. If it is allowed, sign out at once. Run nothing in the session.
4. Run this query (wait about 10 minutes for ingestion):

```kql
// Tables: DisruptionAndResponseEvents (ActionType, PolicyName, ReportType,
// SourceUserName, SessionId), DeviceLogonEvents (ActionType, LogonType, AccountName).
// Returns all columns; no project, the column set differs per table.
let start = datetime(2026-11-25 07:20);   // run as ago(1h) on the day
union withsource=Table
    (DisruptionAndResponseEvents | where Timestamp >= start),
    (DeviceLogonEvents
        | where Timestamp >= start
        | where DeviceName =~ "vm-ir-lab-01" and AccountName =~ "iradmin")
| order by Timestamp asc
```

Result (run 2026-11-25, window `ago(1h)`): 7 `DeviceLogonEvents` rows for `iradmin`,
no `DisruptionAndResponseEvents` row.

| Time (UTC) | ActionType | LogonType | Protocol | Initiating process |
|------------|------------|-----------|----------|--------------------|
| 07:25:31 | LogonSuccess (3 rows, LogonId 1045876) | Network | NTLM | `lsass.exe` |
| 07:25:35 | LogonAttempted | Unknown | – | `svchost.exe` (UserManager) |
| 07:25:35 | LogonSuccess (3 rows, LogonId 1107140) | RemoteInteractive | Negotiate | `lsass.exe`, `svchost.exe` |

Source: the owner's Mac, public IP (not recorded). `IsLocalAdmin` true. The same pattern
as 06:07:23–06:07:24 on 2026-11-24: a Network logon, then RemoteInteractive four seconds
later, both successful, and no containment event.

The VM had just booted: `lsass.exe` started at 07:24:29 UTC, one minute before the
sign-in. So this test is after a reboot, while the 06:07 sign-in was not (no reboot
between the attack and the post-attack capture). Both were allowed.

Policy status, checked by the owner right after the test: Active. Nothing was run in
the session; the owner signed out at once.

A third case, found while checking the "Lateral movement using RDP blocked" alert (its
last activity moved to 08:22:08 on 2026-11-25). The VM auto-shuts down at 08:00 UTC
(19:00 AEDT); the owner started it again and signed in:

| Time (UTC) | Event |
|------------|-------|
| 08:21:43 | VM boots (`wininit.exe` start) |
| 08:21:51 / 08:21:56 | `iradmin` Network (NTLM) then RemoteInteractive logon, success |
| 08:22:08 | `ContainedUserRemoteDesktopSessionDisconnected` (Blocked) and `ContainedUserRemoteDesktopSessionStopped` (Prevented), policy `ContainUser`, session 2, source the owner's Mac |
| 08:22:37 / 08:22:38 | `iradmin` Network then RemoteInteractive logon again, success. No later containment event |

This was 21 minutes after the release (08:00:45, step 2). The VM was off when the
release was sent, so on boot it still enforced the containment.

Across the three cases the pattern is the same: containment ends an RDP session that is
already open, and the account signs straight back in.

| Case | Session ended by containment | Next sign-in | Gap |
|------|------------------------------|--------------|-----|
| 2026-11-24 attack | 06:06:35 | 06:07:24, allowed | 49 s |
| 2026-11-25 test, policy Active | none seen (signed out within about a minute) | 07:25:35, allowed | – |
| 2026-11-25 after reboot | 08:22:08 | 08:22:38, allowed | 30 s |

No `ContainedUserLogonBlocked` event exists in any of them. In this lab, contain user
ends sessions but does not stop new RDP sign-ins. Why is still unconfirmed.

Reading the result:

- Blocked, with a `ContainedUserLogonBlocked` row: containment works now. The 06:07
  sign-in got through for a reason this test does not show. Candidates: [timing right
  after the logoff / other]. Record it as unexplained.
- Allowed again, no disruption row: containment does not stop a new RDP sign-in from
  this source to this device in this lab. Earlier guess: the source Mac is not
  onboarded. Treat this as unconfirmed. The documentation describes blocking on the
  target device, so the source should not matter.

Either way, the PIR records this as evidence, not as a footnote:

> Attack disruption contained the user and ended the open RDP session, but it did not
> stop the same account signing in again 49 seconds later (06:06:35 → 06:07:24) and
> trying the credential dump again (blocked by antivirus at 06:26:38, not by
> containment). Automatic user containment does not replace a manual response: isolate the
> device, and disable or reset the account. Containment does not disable the account.
> A re-test on 2026-11-25 at 07:25 UTC, with the policy still Active, was allowed
> the same way and left no containment event, and after a reboot on the same day the
> account was signed out by containment and signed straight back in 30 seconds later,
> so the gap is reproducible. Why the
> sign-in is not blocked is still unconfirmed.

The README plans a manual "Isolate device". It did not happen during the incident, and
it is not done now after the fact. The PIR records the gap and recommends isolating the
device as soon as the intrusion is confirmed.

## 2. Release the `iradmin` containment

Containment releases itself after up to 5 days. It is released by hand here because
cleanup needs `iradmin` over RDP.

Where the Undo is: not in Action center. Incident 15 → Activities → "iradmin
contained" → Undo at the top of the side panel. The portal answers "Undo process
initiated" and says the result appears in Action center → History.

Record (2026-11-25, UTC):

| Field | Value |
|-------|-------|
| Incident activity | "[iradmin SID] uncontained", type Uncontain |
| Triggered on | 08:00:45 |
| Execution status | Completed |
| Expires on | Expired (the policy is no longer in force) |
| Scope of enforcement | Entire organization |
| Related alert | Compromised account conducting hands-on-keyboard attack |
| Action center History | "Release user containment", 08:00, approval ID 26e9ef, Completed, submitted by the owner |

The portal's own text for the action: it releases the user and restores the default
access settings on the endpoints, and advises reviewing the user and containing again if
needed.

The VM was off when the release was sent (auto-shutdown at 08:00 UTC). The portal showed
the policy as released and expired, but after the next boot the device still ended an
RDP session at 08:22:08 (step 1, third case). A release only reaches a device when it
is online. The portal status says nothing about what the device enforces.

Screenshots show the full SID and the owner's email. They stay outside the repo unless
redacted.

## 3. Custom indicator: block and remediate

Prerequisites (README Design notes): Defender Antivirus in active mode with cloud
protection, and "Allow or block file" on in Settings → Endpoints → Advanced features.
Not checked separately; the blocks in steps 4 and 5 show both were on.

Settings → Endpoints → Indicators → File hashes → Add item:

| Field | Value |
|-------|-------|
| Indicator | `8765f0fee6655cae983f7c1539d3e1cf2735c1c7951171a35fe54e1b140de66e` (SHA256 of `update-svc.exe` / `stub.exe`) |
| Expires on | Never |
| Title | `IR lab incident 15: first-stage payload` |
| Severity | High |
| Generate alert | On |
| Category (of the generated alert) | Malware |
| Action | Block and remediate |
| Scope | All devices |

Indicator created: about 08:15 UTC on 2026-11-25 (owner's estimate; the portal shows
it as the only file indicator in the tenant). The first try was rejected as "indicator
value is not valid"; pasting the bare hash again worked. Propagation can take time. First effect seen: 09:28:18 UTC,
the first time the file was touched (step 4).

## 4. Existing copies removed

Known copies, from a hash search over `DeviceFileEvents` and `DeviceProcessEvents` since
2026-11-24 (only `FileCreated` and `ProcessCreated`, no delete event):

| File | Path when created | Created (UTC, 2026-11-24) | On the VM on 2026-11-25, before the indicator took effect |
|------|-------------------|---------------------------|----------------------------------------------------------|
| `stub.exe` | `C:\simulation\payload-stub\stub.exe` | 05:10:22 (`csc.exe`) | Present at `C:\lab\simulation\payload-stub\stub.exe`, 4096 bytes, LastWriteTime 05:10:22 |
| `update-svc.exe` | `C:\Users\iradmin\AppData\Local\Temp\2\update-svc.exe` | 05:31:11 (created and run) | Not found |

The on-VM check searched `C:\lab`, `C:\AtomicRedTeam`, `C:\Users`, `C:\ProgramData` and
`C:\Windows\Temp`.

- `stub.exe` now sits under `C:\lab`, with its original write time. This confirms that
  `C:\simulation` was moved into `C:\lab`; MDE logged no event for the move.
- `update-svc.exe` is gone, with no delete event. `Temp\2` is the per-session temp
  folder of RDP session 2; a likely reason is that Windows deletes it when the session
  ends. That is not confirmed. Either way it was gone before the indicator was created,
  so it does not count as remediation by the indicator.

So the remediation test rests on one copy: `stub.exe` under `C:\lab`. Check again
about 1 hour after the indicator was created:

```kql
// Tables: DeviceFileEvents (SHA256, FolderPath, ActionType), DeviceEvents
// (SHA256, ActionType such as AntivirusDetection), AlertEvidence (SHA256, AlertId).
let h = "8765f0fee6655cae983f7c1539d3e1cf2735c1c7951171a35fe54e1b140de66e";
let start = datetime(2026-11-25 08:15);
union withsource=Table
    (DeviceFileEvents | where Timestamp >= start and SHA256 == h),
    (DeviceEvents | where Timestamp >= start and SHA256 == h),
    (AlertEvidence | where Timestamp >= start and SHA256 == h)
| order by Timestamp asc
```

Result at about 09:15 UTC (one hour after the indicator): no rows, and
`Test-Path C:\lab\simulation\payload-stub\stub.exe` is True. The indicator did not
touch the dormant copy on its own.

Why, per Microsoft's file indicator documentation: a block indicator stops the file
from being read, written or executed, and it is enforced by Defender Antivirus when the
file is accessed or scanned ("file indicators work with any other scan (RTP or
Custom)"). A file nobody opens is not found by the indicator alone. So the test has to
touch the file.

Second check, without running the file (owner, on the VM):

```powershell
# 1. Read access. Expect access denied and a detection if the block is in force.
Get-FileHash C:\lab\simulation\payload-stub\stub.exe -Algorithm SHA256
# 2. If the read succeeds: custom scan of that one file.
& "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File C:\lab\simulation\payload-stub\stub.exe
# 3. Then
Test-Path C:\lab\simulation\payload-stub\stub.exe
Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 3
```

Result (2026-11-25, VM clock is UTC):

1. `Get-FileHash` failed: "cannot be read: Operation did not complete successfully
   because the file contains a virus or potentially unwanted software". The read was
   blocked.
2. `MpCmdRun -Scan -ScanType 3` failed with `0x80070002` (file not found): the file was
   already gone by then.
3. `Test-Path` False. `Get-MpThreatDetection`, newest entry:

| Field | Value |
|-------|-------|
| Resources | `file:_C:\lab\simulation\payload-stub\stub.exe` |
| InitialDetectionTime | 09:28:18 |
| RemediationTime | 09:28:34 (16 seconds later) |
| ActionSuccess | True |
| ProcessName | `powershell.exe` (the `Get-FileHash` read), user `vm-ir-lab-01\iradmin` |
| DetectionSourceTypeID | 3 (real-time protection) |
| CleaningActionID / ThreatStatusID | 2 / 3 (quarantine / quarantined) |
| ThreatID | 2147718593, ThreatName `EUS:Win32/CustomEnterpriseBlock!cl` (from `MpCmdRun -Restore -ListAll`) |

So the indicator worked on first access: the read was refused and the file was
quarantined within 16 seconds. It did nothing for the hour the file sat untouched.
The threat name `CustomEnterpriseBlock` confirms the detection came from the custom
indicator, not from a signature. The file had sat on disk for 28 hours before the
indicator existed and was never detected.

Alerts (incident 15 alert export), both correlated into incident 15 ("Same file, Same
device"):

| Alert | Severity | Category | Detection source | First activity | Last activity |
|-------|----------|----------|------------------|----------------|---------------|
| 'CustomEnterpriseBlock' malware was prevented | Informational | Malware | Custom TI | 09:28:34 | 09:35:38 |
| An active 'CustomEnterpriseBlock' malware was prevented | Informational | Malware | Custom TI | 09:28:34 | 09:35:38 |

The alerts carry Defender's own titles and Informational severity, not the indicator's
title and High. Why is not confirmed. [check the indicator's alert settings]

Query above (run after step 5): `DeviceEvents` has 3 `OtherAlertRelatedActivity` rows at
09:28:34 for `C:\lab\simulation\payload-stub\stub.exe`, described as "Defender detected
and quarantined 'EUS:Win32/CustomEnterpriseBlock!cl' in file 'stub.exe', preventing
attempted open by 'powershell.exe'". The rest are `AlertEvidence` rows for the two alerts
(file and process entities under `C:\lab\simulation\payload-stub` and `C:\lab\restore`).
No `DeviceFileEvents` row. Nothing for `stub2.exe` (09:38); see step 5.

The same command listed the two step 4 detections of 2026-11-24 (already known, now
with their remediation times):

| Detected | Remediated | Command line | Status |
|----------|------------|--------------|--------|
| 06:02:43 | 06:02:58 | `rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id $env:TEMP\lsass-comsvcs.dmp full` | Removed |
| 06:26:33 | 06:26:47 | `procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass_dump.dmp` | Removed |

## 5. Re-execution blocked

The README requires proof that a re-run is blocked. Step 4 quarantined the last copy.
Rebuilding with `build-stub.ps1` is no test: `csc` is not deterministic by default, so a
new build gets a new SHA256 that the indicator does not match. So the quarantined copy is
restored to a separate folder and run once (owner decision, 2026-11-25).

Owner, on the VM, elevated PowerShell:

```powershell
$mp = "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"
# 1. Find the quarantined item and its threat name.
& $mp -Restore -ListAll
# 2. Restore it to a separate folder (removed with C:\lab in step 8).
New-Item -ItemType Directory C:\lab\restore -Force | Out-Null
& $mp -Restore -Name "EUS:Win32/CustomEnterpriseBlock!cl" -Path C:\lab\restore
Get-ChildItem C:\lab\restore
# 3. Run it once.
(Get-Date).ToUniversalTime()
& C:\lab\restore\stub.exe
# 4. Record.
Test-Path C:\lab\restore\stub.exe
Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 2
```

Possible outcomes:

- Restore refused, or the file is quarantined again as it is written: the indicator
  also blocks writes. Record that. There is nothing to run.
- Restore works and the run fails with a "virus or potentially unwanted software"
  error, plus a new detection: re-execution blocked. This is the expected result.
- The run starts: the block failed. Record it as a finding, not a pass.

Result:

- Step 1: one quarantined item, `EUS:Win32/CustomEnterpriseBlock!cl`,
  `C:\lab\simulation\payload-stub\stub.exe`, quarantined 09:28:34 UTC.
- Step 2: `-FilePath` cannot be combined with `-Name`; the destination switch is
  `-Path`. With `-Path C:\lab\restore` the item "was restored": `stub.exe`, 4096 bytes,
  LastWriteTime 2026-11-24 05:10. Defender's own restore was not blocked, and listing
  the folder does not read the file.
- Step 3, 09:35:38 UTC: **the restored copy ran.** Output: "IR-2026-FIN042 lab stub
  ran. Benign portfolio-lab artifact." No error.
- Step 4: `Test-Path` True. No new detection. The 09:28:18 detection changed after the
  restore: `ThreatStatusID` 3 → 7 and `CleaningActionID` 2 → 9. The two step 4 detections
  of 2026-11-24 are unchanged.

So the re-execution was **not blocked**. This is a finding, not a pass. Likely reason,
unconfirmed: a restore from quarantine tells Defender the owner chose to keep this
detection, so it stops acting on it on this device. Follow-up checks (owner, same session):

| Check | Result |
|-------|--------|
| `Get-MpPreference` threat default actions, path and process exclusions | All empty. The restore added no device-wide allow or exclusion |
| `Get-MpThreat` for 2147718593 | `EUS:Win32/CustomEnterpriseBlock!cl`, IsActive False, DidThreatExecute False |
| `Get-FileHash C:\lab\restore\stub.exe` | Read allowed. SHA256 `8765F0FE…DE66E`, the indicator's hash |
| Copy to `C:\lab\restore\stub2.exe`, then run it | Copy allowed. Run refused: "Program 'stub2.exe' failed to run: … the file contains a virus or potentially unwanted software". Windows Security pop-up: "Content is blocked", "Your administrator does not allow you to access content from stub2.exe" |

Conclusion:

- **Re-execution is blocked.** A new copy with the same SHA256 was refused at run time,
  with the administrator-block message of a custom indicator. This is the README's
  requirement.
- **The restored file is exempt.** The restore exempted that one file only: it can be
  read, copied and run. Nothing shows up in `Get-MpPreference`; the only trace is the
  changed status on the original detection (`ThreatStatusID` 7). The restore needed an
  elevated prompt. An attacker with local admin rights, as `iradmin` had, could use the
  same path to get a quarantined payload back and run it. PIR recommendation: alert on
  quarantine restores, and do not give everyday accounts local admin.
- The alert misreports the restored run. Its evidence lists the 09:35:38 `stub.exe`
  process in `C:\lab\restore` with state "Blocked", and the alert is titled "An active
  … malware was prevented". The process did run and printed its output. Trust the host,
  not the label.
- Detection for `stub2.exe`: detected 09:38:20, quarantined 09:38:33 (13 seconds),
  ThreatID 2147718593 (`CustomEnterpriseBlock`), real-time protection, process
  `powershell.exe`, user `iradmin`, `ThreatStatusID` 3 (quarantined), ActionSuccess
  True. It raised no alert of its own. Incident 15 has only the two Custom TI alerts,
  both with first activity 09:28:34 and last activity 09:35:38, correlated into the
  incident at 09:29:26 and 09:39:29 (incident Activities export, taken 11:12). No later
  Custom TI alert or correlation.
- `C:\lab\restore\stub.exe` is still on disk and exempt. It goes with `C:\lab` in
  step 8; check it is gone.

Alerts and query rows for this step: see step 4 (the two Custom TI alerts run to
09:35:38).

Not blocked by hash, on purpose: `rundll32.exe`, `comsvcs.dll` and the signed
`procdump.exe` (README Design notes).

## 6–9. Cleanup

`\spawn` through live response (the README plans `remediate` for persistence):

```console
scheduledtasks spawn
remediate scheduledtask spawn
remediate list
```

Command log (2026-11-25, UTC):

| Start | Command | Parameters | Entities | Duration | Status |
|-------|---------|------------|----------|----------|--------|
| 10:00:06 | connect | | | 2 s | Completed |
| 10:00:14 | scheduledtasks | spawn | 1 | 1 s | Completed |
| 10:00:29 | remediate | scheduledtask spawn | | 12 s | Completed |

`remediate list` and the second `scheduledtasks spawn` were not run. The `schtasks` check
below shows the task is gone.

The rest over RDP as `iradmin`, in an elevated PowerShell:

```powershell
# 7. Test account
Get-LocalUser -Name 'T1136.001_Admin'
Remove-LocalUser -Name 'T1136.001_Admin'
Test-Path 'C:\Users\T1136.001_Admin'   # a profile exists only if it ever signed in

# 8. Operator working folder (includes C:\lab\simulation)
Get-ChildItem C:\lab -Recurse | Measure-Object
Remove-Item C:\lab -Recurse -Force
Test-Path C:\simulation               # moved into C:\lab (stub.exe found there)

# 9. Atomic Red Team (includes ExternalPayloads\procdump.exe)
Remove-Item C:\AtomicRedTeam -Recurse -Force

# Check
schtasks /query /tn spawn
Get-LocalUser | Select-Object Name, Enabled
Get-LocalGroupMember Administrators
Test-Path C:\lab, C:\AtomicRedTeam
```

Output (owner, started 10:02:38 UTC; per-step times after that are approximate):

- `Get-LocalUser T1136.001_Admin`: present, Enabled True. Removed. `C:\Users\T1136.001_Admin`
  does not exist (the account never signed in).
- `C:\lab`: 12 items (files and folders), removed. `C:\simulation`: does not exist.
- `C:\AtomicRedTeam`: removed, no error.
- Check: `schtasks /query /tn spawn` → "The system cannot find the file specified".
  Local users: DefaultAccount, Guest, iradmin, WDAGUtilityAccount; only `iradmin` enabled.
  Administrators: `vm-ir-lab-01\iradmin` only. `Test-Path` on `C:\lab`,
  `C:\AtomicRedTeam` and `C:\lab\restore\stub.exe`: False, False, False.

Not removed here: the Invoke-AtomicRedTeam PowerShell module, if it was installed.
`Get-Module -ListAvailable Invoke-AtomicRedTeam` returned nothing, so no module is left
in the module path. The VM goes with
`terraform destroy` at the end of the project.

## 10. Verify cleanup in advanced hunting

```kql
// Tables: DeviceEvents (ActionType such as ScheduledTaskDeleted, UserAccountDeleted,
// UserAccountRemovedFromLocalGroup; AdditionalFields), DeviceFileEvents (FileDeleted,
// FolderPath).
let start = datetime(2026-11-25 10:00);
union withsource=Table
    (DeviceEvents
        | where Timestamp >= start and DeviceName =~ "vm-ir-lab-01"
        | where ActionType in ("ScheduledTaskDeleted", "UserAccountDeleted",
            "UserAccountRemovedFromLocalGroup")),
    (DeviceFileEvents
        | where Timestamp >= start and DeviceName =~ "vm-ir-lab-01"
        | where ActionType == "FileDeleted"
        | where FolderPath startswith @"C:\lab" or FolderPath startswith @"C:\AtomicRedTeam")
| summarize Events = count(), First = min(Timestamp), Last = max(Timestamp)
    by Table, ActionType
```

Result:

| Table | ActionType | Events | First (UTC) | Last (UTC) |
|-------|------------|--------|-------------|------------|
| DeviceEvents | UserAccountDeleted | 1 | 10:02:47 | 10:02:47 |
| DeviceEvents | UserAccountRemovedFromLocalGroup | 2 | 10:02:47 | 10:02:47 |
| DeviceFileEvents | FileDeleted | 48 | 10:03:01 | 10:03:10 |

- The account deletion and its removal from both groups (Users and Administrators, the
  two it was added to at 05:52:17 on 2026-11-24) are logged.
- 48 file deletions under `C:\lab` and `C:\AtomicRedTeam` in 9 seconds. MDE does not log
  every file, so this is not a full count of what was removed.
- No `ScheduledTaskDeleted` for `\spawn`. The live response `remediate` at 10:00:29
  left no event in this table. The proof that it is gone is the live response log
  and `schtasks /query`.

Keep the CSV; do not rely on a screenshot (walkthrough, wrong turns).
