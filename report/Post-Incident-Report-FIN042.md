# Post-incident report: IR-2026-FIN042

| | |
|---|---|
| Client | [fictional client] |
| Case | IR-2026-FIN042 |
| Ticket | ServiceNow INC0010004 |
| Defender incident | 15 |
| Affected host | `vm-ir-lab-01` (Windows Server 2022, Azure) |
| Attack date | 2026-11-24 |
| Response date | 2026-11-25 |
| Status | Closed 2026-11-25 11:12 UTC, true positive |

> The client and case are fictional. Every time, alert and query result in this report
> comes from a real run on the lab machine. Times are UTC.

## 1. Summary

On 24 November 2026 someone signed in to server `vm-ir-lab-01` over Remote Desktop
with the local administrator account `iradmin` and, by hand, ran an unknown program,
set up a scheduled task, created a second administrator account, and twice tried to
copy the passwords held in memory (LSASS). Microsoft Defender stopped both password-theft
attempts, so no credentials were taken. Defender contained the account 13 minutes after the first alert and ended its open
session, but the same account signed straight back in,
and the server was never isolated from the network. We found no sign that the attacker
reached any other machine. The program, the task and the extra account have been
removed, and the program is now blocked on every onboarded device by its file hash.

Severity: High. The account had full control of the server. Credential theft failed.

Main recommendations: isolate a host as soon as an intrusion is confirmed, disable or
reset the compromised account rather than relying on automatic containment, and stop
using a shared local administrator account for everyday sign-in.

## 2. Timeline

| Time (UTC) | Event | Evidence |
|------------|-------|----------|
| 2026-11-24 04:41:05 | `iradmin` signs in over RDP (session 2) | DeviceLogonEvents |
| 05:31:10 | Encoded PowerShell downloads `update-svc.exe` into the user's Temp folder and starts it. No built-in alert | DeviceEvents (PowerShellCommand), DeviceFileEvents |
| 05:45:32 | Scheduled task `\spawn` created to start `cmd.exe`. First alert: "Masqueraded task or service" | DeviceProcessEvents, alert |
| 05:45:33 | High alerts: "Compromised account conducting hands-on-keyboard attack" | Alert |
| 05:52:17 | Local account `T1136.001_Admin` created and added to Administrators | DeviceProcessEvents, DeviceEvents |
| 05:58:59 | Defender attack disruption contains `iradmin` | Action center |
| 06:02:43 | First LSASS dump attempt (`rundll32` + `comsvcs.dll`), blocked and removed by antivirus at 06:02:58 | Get-MpThreatDetection, alert |
| 06:06:35 | Containment ends the open RDP session | DeviceEvents (ContainedUserRemoteDesktopSessionStopped) |
| 06:07:24 | `iradmin` signs in again over RDP, 49 seconds later; not blocked | DeviceLogonEvents |
| 06:26:33 | Second LSASS dump attempt (ProcDump), blocked and removed at 06:26:47 | Get-MpThreatDetection, alert |
| 2026-11-25 07:22:11 | Disk snapshot taken to preserve evidence | Azure snapshot |
| 08:00:45 | Account containment released for cleanup | Incident activity |
| about 08:15 | Payload hash added as a block-and-remediate indicator | Indicator |
| 09:28:34 | Last copy of the payload quarantined on first read | Get-MpThreatDetection |
| 09:38:20 | New copy with the same hash blocked when run (quarantined 09:38:33) | Get-MpThreatDetection |
| 10:00:41 | Scheduled task `\spawn` removed | Live response log |
| 10:02:47 | Account `T1136.001_Admin` removed | DeviceEvents (UserAccountDeleted) |
| 10:03:10 | Attacker working folders removed; cleanup confirmed in hunting | DeviceFileEvents |
| 10:59:04 | Incident acknowledged (status Open, assigned) | Incident activities |
| 11:12:09 | Incident closed, true positive | Incident activities |

## 3. Findings

**Entry.** The attacker used valid credentials for `iradmin` over RDP. How they were
obtained is outside this investigation.

**Execution.** An encoded PowerShell command downloaded `update-svc.exe` from a cloud
storage URL and ran it. The command line only showed `-EncodedCommand`; the decoded
command was recovered from Defender's PowerShell events. No built-in alert fired for
this step; a custom detection now covers it.

**Persistence.** Scheduled task `\spawn`, set to run `cmd.exe` once at 20:10.

**Privilege.** New local administrator `T1136.001_Admin`, created with `net user /add`
and `net localgroup administrators /add`. It was never used to sign in.

**Credential access (prevented).** Two attempts to dump LSASS memory, first with the
built-in `rundll32` and `comsvcs.dll`, then with Microsoft's signed ProcDump tool.
Defender Antivirus blocked both before the process started. No dump file exists.

## 4. Scope

- **Hosts:** `vm-ir-lab-01` only. A hunt for the incident's accounts and file hashes
  across all onboarded devices found nothing on any other device. Limit: the tenant has
  one onboarded device (`DeviceInfo`, distinct device count 1, run 2026-11-25), so this
  hunt cannot show spread to machines that are not onboarded. A real estate would need
  the same hunt across every device, plus sign-in logs for the account.
- **Accounts:** `iradmin` (used by the attacker), `T1136.001_Admin` (created, unused).
- **Data:** no evidence of data access or exfiltration. Credentials were not dumped.
- **Lateral movement:** none seen.

## 5. Response

Order followed: scope first, then containment, then forensics and cleanup.

| Action | Time (UTC) | Result |
|--------|------------|--------|
| Automatic user containment (attack disruption) | 2026-11-24 05:58:59 | Ended the open RDP session at 06:06:35. Did **not** stop new RDP sign-ins: the account signed in again at 06:07:24 |
| Device isolation | Not done | Gap. See below |
| Evidence preservation (incremental disk snapshot) | 2026-11-25 07:22:11 | Preserved, not analysed |
| Containment released | 08:00:45 | Needed to sign in for cleanup |
| Remove scheduled task `\spawn` (live response) | 10:00:41 | Removed |
| Remove account `T1136.001_Admin` | 10:02:47 | Removed; account deletion logged |
| Remove attacker working folders | 10:03:10 | Removed |

Response times, from Defender incident 15 (same definition as the earlier Sentinel SOC
project: acknowledge = first status change away from New):

| Measure | From | Value |
|---------|------|-------|
| Time to contain (automatic) | First chain alert 05:45:32 to containment 05:58:59 | 13 min 27 s |
| Time to acknowledge | First chain alert 05:45:32 to status Open, 2026-11-25 10:59:04 | 29 h 13 min 32 s |
| Time to resolve | First chain alert 05:45:32 to status Closed, 2026-11-25 11:12:09 | 29 h 26 min 37 s |

The response itself started within minutes (automatic containment) and the cleanup was
done the next day, but the incident stayed New in the queue throughout. It was only
acknowledged after the cleanup. The queue status did not reflect the work.

**Containment gap.** Automatic user containment ended open sessions but did not block
new ones. This was reproduced twice on 2026-11-25 (07:25, while the containment was
still active, and 08:22, after a reboot), each time with no blocked-logon event. Why is
not confirmed. During the incident the attacker used this gap to try the credential
dump a second time, which antivirus stopped, not containment. The device was not
isolated during the incident or afterwards.

## 6. Prevention

The payload's SHA256 was added as a tenant-wide file indicator, action block and
remediate (about 08:15 on 2026-11-25). What it did:

- A copy left untouched on disk was not removed on its own. It was quarantined the first
  time it was read (09:28:18, quarantined 09:28:34).
- A new copy with the same hash was refused at run time (09:38:20). This block raised
  no alert of its own: both indicator alerts in the incident end at 09:35:38.
- A copy restored from quarantine by an administrator **did run** (09:35:38), while the
  alert reported it as blocked. A restore exempts that one file.
- The alerts arrived as Informational with Defender's own titles, not the indicator's
  title. The saved indicator (checked 2026-11-25) has Generate alert ticked and the
  title set, but Alert severity and Category are empty, so High was never stored. That
  fits the Informational severity. Why the title was not used is not confirmed.

Not blocked by hash, on purpose: `rundll32.exe`, `comsvcs.dll` and the signed ProcDump.
They are legitimate tools; a hash block would break normal use and an attacker can switch
tools. They are covered by antivirus behaviour detection and by custom rule 4.

## 7. Recommendations

Short term:

1. Isolate the device as soon as an intrusion is confirmed. Do not wait for forensics.
2. Disable or reset a compromised account by hand. Automatic containment does not
   disable it and, here, did not stop new sign-ins.
3. Alert on restores from quarantine, and restrict who can restore.
4. Keep the four custom detection rules, with incident correlation on for each.
5. Acknowledge and assign the incident before acting on it, so the queue shows who
   owns it and acknowledge and resolve times can be measured.

Long term:

1. Remove everyday use of the local administrator account; use named accounts with
   just-in-time admin rights, and Windows LAPS for the local admin password.
2. Allow RDP only through a managed path (for example Azure Bastion), not from the
   internet.
3. Turn on LSA protection (RunAsPPL) and Credential Guard to make LSASS harder to dump.
4. Investigate why user containment did not block new RDP sign-ins before relying on it.

## 8. Indicators of compromise

| Type | Value | Note |
|------|-------|------|
| SHA256 | `8765f0fee6655cae983f7c1539d3e1cf2735c1c7951171a35fe54e1b140de66e` | Payload, blocked by indicator |
| File | `update-svc.exe` in `C:\Users\<user>\AppData\Local\Temp\2\` | Payload as downloaded |
| File | `stub.exe` | Same hash, staging copy |
| URL | `hxxps://[lab storage account][.]blob[.]core[.]windows[.]net/lab/stub[.]exe` | Download source |
| Scheduled task | `\spawn` → `C:\windows\system32\cmd.exe`, once at 20:10 | Persistence |
| Account | `T1136.001_Admin` (local, Administrators) | Created by attacker |
| Account | `iradmin` (local, RID 500) | Used by attacker |
| Command | `rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <lsass pid> ... full` | Blocked |
| Command | `procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass_dump.dmp` | Blocked |

The account's password appeared in clear text in Defender's process events and is not
reproduced here.

## 9. MITRE ATT&CK mapping

| Tactic | Technique | Observed |
|--------|-----------|----------|
| Initial access / Persistence | T1078.003 Valid accounts: local accounts | `iradmin` signed in over RDP |
| Execution | T1059.001 PowerShell | Encoded download and run |
| Persistence | T1053.005 Scheduled task | `\spawn` |
| Persistence | T1136.001 Create account: local account | `T1136.001_Admin` |
| Credential access | T1003.001 LSASS memory | Two attempts, both prevented |

## Appendix

- Investigation walkthrough, including wrong turns: `investigation/walkthrough.md`
- Response record and queries: `investigation/response.md`
- Detection rules and tuning: `detections/`
- Scope query: `investigation/hunting/scope-check.kql`
- Ticket: `itsm/ticket.md`
