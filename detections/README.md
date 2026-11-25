# Detections

Four custom detection rules, one per attack step, so each step gets its own alert.
Field names come from real events on `vm-ir-lab-01` (2026-11-24 run), not from guesses.

| File | Step | ATT&CK | Verified on real data |
|---|---|---|---|
| `01-powershell-download-exe-temp.kql` | 1 Payload download and start | T1059.001 | Yes |
| `02-schtasks-create-shell-action.kql` | 2 Scheduled task | T1053.005 | Yes |
| `03-net-add-local-admin.kql` | 3 New local admin | T1136.001 | Yes |
| `04-lsass-dump-tooling.kql` | 4 LSASS dump | T1003.001 | Branch B yes; branch A cannot be (attack was blocked) |

## Rule settings (Defender portal → Hunting → Custom detection rules)

- Frequency: every hour (scheduled). Scheduled rules scan events that existed before
  the rule was saved; NRT rules do not (capability test, 2026-11-23).
- Lookback must cover the attack (2026-11-24 05:25–06:30 UTC).
- Each query keeps `Timestamp`, `ReportId` and `DeviceId`, which custom detections need.
- Impacted entities: Device and User, as listed in each file, so the alerts join the
  same incident as the built-in ones.
- Scope: device group `lab-edr-ir`. Response actions: none (the owner acts by hand).
- After saving, open the rule page and check the saved query.

Per rule:

| Rule | Name | Severity | Category | Technique | User entity | File evidence |
|---|---|---|---|---|---|---|
| 1 | IR-LAB 01 PowerShell wrote EXE to user Temp | Medium | Execution | T1059.001 | `InitiatingProcessAccountSid` | `SHA256` |
| 2 | IR-LAB 02 schtasks create with shell action | Medium | Persistence | T1053.005 | `AccountSid` | - |
| 3 | IR-LAB 03 net add local admin | Medium | Persistence | T1136.001 | `AccountSid` | - |
| 4 | IR-LAB 04 LSASS dump tooling | High | Credential access | T1003.001 | `AccountSid` | `SHA256` |

Device entity is `DeviceId` for all four.

## Results

Hunting runs on 2026-11-24 (before saving). Every expected event came back, and no
other rows: no Atomic install noise, no false positives in this window.

| Rule | Hunting run over 2026-11-24 | Alert after save | Incident |
|---|---|---|---|
| 1 | 1 row: `update-svc.exe`, 05:31:11 UTC, `Ran = true` | Yes, 1 alert, joined incident 15 | 15 |
| 2 | 1 row: `SCHTASKS /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 20:10`, 05:45:32 UTC | Yes, incident created 11:51:08 UTC | 16 |
| 3 | 4 rows: `net` / `net1` `user /add` and `localgroup administrators "T1136.001_Admin" /add`, 05:52:17 UTC | Yes, 4 incidents created 11:53:42–43 UTC. After tuning: 1 alert, joined 15 | 17, 18, 19, 20; then 15 |
| 4 | Branch A 0 rows. Branch B 3 rows: `procdump.exe` x2, `procdump64.exe`, 06:26:26 UTC | Yes, 2 incidents created 11:55:26–28 UTC | 21, 22 |

From the incident list export (2026-11-24, after saving the rules):

- All rules backfilled the attack window, as the capability test predicted.
- Incident names came out as "TEST reg query HKCU 2/3/4", not the IR-LAB names: the alert
  title field was not changed from the old test rule. The owner changed the alert
  titles to the IR-LAB names (2026-11-24); alerts already raised keep the old titles.
- Rules 2–4 did not join incident 15, although they share the host and `iradmin`.
  Each alert opened its own incident (16–22, all New). The README's design note
  expected entity mapping to correlate them.
- Incident 15 now has 20 active alerts (18 before). Its alert export shows one custom
  detection alert: rule 1 (still titled "TEST reg query HKCU", first activity
  05:31:11 UTC). Its correlation reason is "Same device" only, and its account shows as
  a SID, not `iradmin`; the built-in alerts in 15 show "Same device, Same user
  credentials". Rules 2 and 4 did not join because incident correlation was off on
  them (see Tuning notes).
- `AlertInfo` (custom detection) lists 8 alerts: rule 1 x1, rule 2 x1,
  rule 3 x4 (05:52:17), rule 4 x2 (06:26:26). For these backfilled alerts,
  `AlertInfo.Timestamp` is the event time (05:31–06:26 UTC), not the time the alert
  was raised (11:38–11:55 UTC), so a filter on the raise time returns nothing.
- Rule 3 raised 4 alerts for one admin-add (one per row: `net` and `net1` for each of
  two commands), and rule 4 raised 2 alerts for 3 rows. Rule 3 maps Device and User,
  with no evidence entities, and incident correlation is on. The 2026-11-23 capability
  test mapped only the device (its incident shows "1 Host"), and 3 rows gave 1 alert.
  Cause of the split not confirmed.

ProcDump hashes (signed Sysinternals tool, not for a block indicator):
`procdump.exe` 099fd0cd771b583d283814a225a8fbbdb3faa47cc8a644568d6201893ad76bd9,
`procdump64.exe` 22c2a2b09ade73a342a18dab838354385f73fc98e324b9903fd61fff949c5124.

## Tuning notes

### Rule 3: one admin-add, four alerts

- **Fired first:** 4 alerts and 4 incidents (17–20) for one action at 05:52:17 UTC:
  `net.exe` and `net1.exe` for `user /add`, and again for `localgroup administrators /add`.
  An analyst gets four tickets for one event.
- **Changed:** the query now collapses rows to one per device, account and 5-minute
  window, keeping the first event's `Timestamp` and `ReportId`, and lists every
  command line in `Commands`. Same filter, same entities.
- **Fired after:** hunting returned 1 row, `Events = 4`. After saving the edited rule,
  it raised 1 new alert, which joined incident 15 (2026-11-25).

### Incident correlation off on rules 2 and 4

- **Fired first:** rules 2 and 4 each opened their own incidents (16, 21, 22) instead of
  joining incident 15.
- **Cause:** incident correlation was not enabled on those two rules (owner check,
  2026-11-25). Entity mapping alone does not pull an alert into an existing incident.
- **Changed:** incident correlation turned on for rules 2 and 4.
- **After:** applies to new alerts only; the existing alerts in 16, 21 and 22 stay where
  they are. The owner linked them into incident 15 by hand ("Link alert to another
  incident", 2026-11-25): rule 2's alert from 16 and rule 4's two alerts from 21 and 22.
  Incident 15 count: 20 alerts → 21 (tuned rule 3, automatic) → 24 (3 linked by hand).
  So of the four custom rules, rules 1 and 3 joined by correlation and rules 2 and 4
  were linked manually. Incidents 17–20 (rule 3's pre-tuning duplicates) were closed
  as True positive, determination Other (2026-11-25); the tuned rule 3 alert in 15
  replaces them.
