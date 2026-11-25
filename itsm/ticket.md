# ServiceNow incident: IR-2026-FIN042

One incident in a free ServiceNow developer instance (PDI), raised and worked by hand.
No automation, not in Terraform or CI (README Design notes). This file is the field
snapshot, from the real ticket INC0010004 (2026-11-25).

Times are UTC. The PDI shows America/Los_Angeles (UTC−8 in November), confirmed in the
PDI user preferences.

## Raised after the response, not during it

The plan was to open the ticket when the chain ran. It was not: the attack ran on
2026-11-24 and the response on 2026-11-25, and the ticket is raised afterwards. So the
ticket's own created / in progress / resolved times measure the paperwork, not the
response. They are not used as MTTA or MTTR.

MTTA and MTTR come from Defender incident 15 instead (see Measurement). The ticket
carries the response record as work notes, with the real times written in each note.

## Fields as entered

| Field | Value |
|-------|-------|
| Caller | System Administrator (the analyst raising it from the Defender alert) |
| Category / Subcategory | Inquiry / Help / Antivirus (the PDI has no Security category; closest match) |
| Configuration item | Empty (the PDI has no CI for the lab VM) |
| Short description | `IR-2026-FIN042: hands-on-keyboard intrusion on vm-ir-lab-01 (Defender incident 15)` |
| Impact / Urgency | 2 - Medium / 1 - High (one host; compromised local admin account) |
| Priority | 2 - High (set by ServiceNow from impact and urgency) |
| Assignment group / Assigned to | Empty / System Administrator |
| Description | See below |

Description (as entered):

```text
Defender XDR incident 15 on vm-ir-lab-01 (lab, fictional client).
Local admin account iradmin ran an encoded PowerShell download of an unknown EXE,
created scheduled task \spawn, added local admin T1136.001_Admin, and tried twice to
dump LSASS (both blocked by Defender Antivirus). Attack disruption contained iradmin.
Scope from hunting: one host. Response and evidence: investigation/response.md.
```

## Work notes

One line per step of the response, posted together as one work note. Each line starts
with the real time of the action (UTC), so the ticket holds the timeline even though it
was written afterwards.

| # | Note (action time, UTC) | Source |
|---|-------------------------|--------|
| 1 | 2026-11-24 05:45:32 First chain alert "Masqueraded task or service" in incident 15. Triage: `iradmin` treated as compromised | walkthrough.md §1 |
| 2 | 2026-11-24 05:58:59 Attack disruption contained `iradmin`; RDP session ended 06:06:35; account signed in again 06:07:24 | walkthrough.md §3 |
| 3 | 2026-11-25 Scope check: no other device, one host | walkthrough.md §4 |
| 4 | 2026-11-25 07:22:11 Evidence snapshot `snap-ir-lab-01-evidence-20261125T072126Z` | response.md §0 |
| 5 | 2026-11-25 07:25:31 RDP re-test while contained: allowed | response.md §1 |
| 6 | 2026-11-25 08:00:45 Containment released | response.md §2 |
| 7 | 2026-11-25 about 08:15 File indicator, block and remediate, payload SHA256 | response.md §3 |
| 8 | 2026-11-25 09:28:34 Dormant payload copy quarantined on first read | response.md §4 |
| 9 | 2026-11-25 09:38:20 Fresh copy with the same hash blocked at run time | response.md §5 |
| 10 | 2026-11-25 10:00:41 `\spawn` removed (live response `remediate`) | response.md §6 |
| 11 | 2026-11-25 10:02:47 `T1136.001_Admin` removed | response.md §7 |
| 12 | 2026-11-25 10:03:10 `C:\lab` and `C:\AtomicRedTeam` removed; cleanup verified in hunting | response.md §8–10 |
| 13 | 2026-11-25 10:59:04 Defender incident 15 acknowledged (Open, assigned); 11:12:09 closed, True Positive / Multi-Staged Attack | Incident 15 Activities |

Never paste the new account's password. MDE shows it in clear text in process events
and on incident graph labels.

## Resolution

| Field | Value |
|-------|-------|
| Resolution code | Resolved by caller |
| Resolution notes | Closed by Caller |

The Resolve button in the Self Service view filled these defaults. Intended text, not
entered: code Solved (Permanently), notes `Persistence and test account removed, payload
blocked tenant-wide by hash. Device was not isolated (gap, see PIR). Report:
report/Post-Incident-Report-FIN042.md`.

## Ticket snapshot (from the real ticket)

| Field | Value |
|-------|-------|
| Number | INC0010004 |
| Priority | 2 - High (Impact 2 - Medium, Urgency 1 - High) |
| Opened | 2026-11-25 11:55:59 (PDI 03:55:59) |
| Impact set | 12:04:01 (PDI 04:04:01) |
| In Progress, assigned | 12:08:16 (PDI 04:08:16) |
| Work notes (13 lines, one post) | 12:11:22 (PDI 04:11:22) |
| Resolved | 12:11:43 (PDI 04:11:43) |

The work notes went in as one post, so the ticket's activity stream does not show the
steps one by one; the real time of each step is written in the line.

## Measurement

Decided (owner, 2026-11-25): MTTA and MTTR come from Defender incident 15, not from
the ticket. Same definition as `project-Sentinel-SOC` (`docs/sla.md`): time to
acknowledge = first change away from New minus the incident's created time.

Where to read the times: incident 15 → Activities. Record the first status change away
from New (who and when) and the change to Resolved. Convert the portal's AEDT to UTC.

| Measure | From | To | Value |
|---------|------|----|-------|
| Time to acknowledge | Incident 15 created 2026-11-24 04:49:03 | Status New → Open and assigned to the owner, 2026-11-25 10:59:04 | 30 h 10 min 01 s |
| Time to contain (automatic) | First chain alert 05:45:32 | Attack disruption contains `iradmin` 05:58:59 | 13 min 27 s |
| Time to resolve | Incident 15 created 2026-11-24 04:49:03 | Status Open → Closed, 2026-11-25 11:12:09 | 30 h 23 min 06 s |
| Time to acknowledge, from the chain | First chain alert 2026-11-24 05:45:32 | 2026-11-25 10:59:04 | 29 h 13 min 32 s |
| Time to resolve, from the chain | First chain alert 2026-11-24 05:45:32 | 2026-11-25 11:12:09 | 29 h 26 min 37 s |

Why acknowledge is so late: the whole response (containment, preservation, indicator,
cleanup) was done in the portal while incident 15 stayed New. Nobody acknowledged it in
the queue until the owner set it to Open after cleanup. The time is recorded as it is,
not backdated. Times are from the incident 15 Activities export (2026-11-25).

Closed at 11:12:09 as True Positive, determination Multi-Staged Attack, with closing
notes. The closing notes were edited afterwards to name ticket INC0010004. The 13 minutes from Open to Closed is only the time to click through:
the work itself was done before the incident was acknowledged.

Incident 15 was created at 04:49:03 for the Atomic Red Team install alerts, an hour
before the chain started, so each measure is given from both start points. The Sentinel-SOC baseline numbers are the comparison
point only; they are not restated here as this project's results.

## Screenshots (`itsm/screenshots/`)

- `01-new.png`, `02-in-progress.png`, `03-resolved.png`: the form at each state.
- `04-work-notes.png`: the activity stream.

Before saving: no password, no subscription or tenant ID, no email address, IPs defanged.
