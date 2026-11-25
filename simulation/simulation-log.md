# Simulation log - IR-2026-FIN042 (fictional case, real lab telemetry)

One run of the four-step chain against the lab VM. Fill this in as the run goes:
one row per step with the Atomic test number used, the start time, the exact
command, and the screenshot. All values come from the real run - leave
`[placeholder]` until then, do not guess.

- Run by: owner, by hand on the lab VM, lab account only.
- VM: `vm-ir-lab-01`
- Run date (UTC): 2026-11-24 (steps 1-4 recorded; step 4 attempted and PREVENTED)
- Invoke-AtomicRedTeam version: `[placeholder]`

## Pre-run environment note - AV at install time

Context, not an attack step. On 2026-11-24, installing the framework with
`Install-AtomicRedTeam -getAtomics` made Defender quarantine the known-bad sample
files bundled in the atomics library on download (real-time + cloud protection on).
`Get-MpThreat` listed 56 signatures - representative: `HackTool:Win32/Powersploit`,
`HackTool:PowerShell/PowerSploit.F`, `VirTool:Win32/Meterpreter`,
`Trojan:Win64/ShellcodeRunner`, `VirTool:Script/CmstpExec.A`. These are library
contents, not output of our chain.

- No AV exclusion was added for the atomics folder (deliberate: the lab is built to
  be detected; adding one would blind the detections).
- Impact on our four tests: none expected. All four use built-in / system tooling
  (schtasks, net user, comsvcs LotL) or a custom harmless PE we control. Step 4 uses
  comsvcs, not the PowerSploit `Out-Minidump.ps1` alternative - which is among the
  quarantined PowerSploit signatures, a second reason to keep comsvcs.
- Per-test prereqs still verified with `-GetPrereqs` before each run.
- Side effect in the Defender portal: the quarantined samples raised alerts that
  XDR correlated into one noisy case, "ID 15: Multiple threat families detected
  including Ransomware on one endpoint" (High, device `vm-ir-lab-01`). This is
  install noise, not the four-step chain. The investigation narrative starts from
  the step-4 LSASS behavioural alert; keep this case separate and decide whether to
  dismiss it in the investigation phase.

## Steps

| # | Technique | Atomic test | Start time (UTC) | Command (as run) | Screenshot |
|---|-----------|-------------|------------------|------------------|------------|
| 1 | T1059.001 - Encoded PowerShell, download and execute | custom #1 (`.\atomics`) | `[placeholder - from portal]` | `Invoke-AtomicTest T1059.001 -PathToAtomicsFolder .\atomics -TestNumbers 1 -InputArgs @{payload_url=<SAS>}` | `[placeholder]` |
| 2 | T1053.005 - Scheduled task persistence | #2 "Scheduled task Local" | 2026-11-24 16:45:32 (portal TZ) | `Invoke-AtomicTest T1053.005 -TestNumbers 2` | `[placeholder]` |
| 3 | T1136.001 - New local administrator account | #8 "Create a new Windows admin user" | 2026-11-24 04:52 (portal TZ) | `Invoke-AtomicTest T1136.001 -TestNumbers 8` | `[placeholder]` |
| 4 | T1003.001 - LSASS dump (LotL) - credential access, **PREVENTED** | #2 comsvcs (+ #1 procdump, both blocked) | 2026-11-24 06:02:43 (portal TZ) | `Invoke-AtomicTest T1003.001 -TestNumbers 2` then `... -TestNumbers 1` | `[placeholder]` |

Observed artifacts (from advanced hunting, as confirmed on the real run):
- Step 1: `update-svc.exe` in `%TEMP%` (SHA256 in the step-1 payload section);
  encoded `powershell.exe` + the blob download in DeviceNetworkEvents.
- Step 2: scheduled task `spawn` (`/SC ONCE /TR C:\windows\system32\cmd.exe /ST 20:10`);
  process chain `powershell.exe -> cmd.exe -> schtasks.exe` in DeviceProcessEvents,
  2026-11-24 16:45:32, account `iradmin`. DeviceEvents had no ScheduledTask ActionType;
  the schtasks process line is the detection anchor.
- Step 3: local admin `T1136.001_Admin` created by `iradmin`. DeviceProcessEvents
  (the "how"): `net user /add ... "[REDACTED]"` then
  `net localgroup administrators "T1136.001_Admin" /add`, each via `cmd.exe -> net1.exe`.
  DeviceEvents (the "outcome", detection anchor): `UserAccountCreated` (account
  `t1136.001_admin`), then `UserAccountAddedToLocalGroup` for `Users` and for
  `Administrators` (group names in AdditionalFields). Both tables hit; the rule anchors
  on DeviceEvents and uses DeviceProcessEvents for command-line context.
- Step 4: credential access PREVENTED. The attacker's LSASS-dump attempts were blocked
  at process launch, so there is NO `comsvcs` / `procdump` / `rundll32` line in
  DeviceProcessEvents - the process never started. The signal is the AV detection, not
  a process event: `Get-MpThreatDetection` ThreatID `2147793100`, 2026-11-24 06:02:43,
  ProcessName `Unknown`, Resource `CmdLine:...` (command-line behaviour detection on the
  comsvcs dump command). Hunt it in DeviceEvents (`AntivirusDetection`) / AlertEvidence,
  not DeviceProcessEvents. The 4:47 detections referencing `C:\AtomicRedTeam\...` are
  install-time library quarantine (see pre-run note), not this step.

## Step 1 payload (for the block indicator)

Step 1 must drop a PE (`.exe` / `.dll`). Its SHA256 is promoted to a
block-and-remediate custom indicator in the response phase.

Mechanism (verified 2026-11-24): no stock T1059.001 test does encoded-PowerShell ->
download -> land a PE and run it, so step 1 is a custom atomic (see "Candidate tests"
and the step-1 note below). Its payload URL points at a **harmless PE**, so step 1
really pulls an `.exe` over the network and lands it on disk. That PE's SHA256 is the
step-6 block indicator. The indicator stays in step 1 - it is not moved to another
step. This is inside the approved design (plan doc S7.5 pre-authorised a PE drop).

Three constraints for the harmless PE:
1. Not known-bad. Its own hash must not trip AV on its own (e.g. a self-compiled
   benign stub, or a renamed signed-but-harmless EXE). It must be blocked LATER
   only because we add its hash to the custom indicator by hand - that is what the
   block-indicator demo is showing. A file AV already flags defeats the point.
2. Lands on disk, not memory-only. No disk file means no hash to block and nothing
   for `remediate` to delete.
3. A real network download cradle, not a local copy, so `DeviceNetworkEvents` has
   the download and matches the tables noted for step 1.

Decided: option A, a self-compiled benign stub. Source `payload-stub/stub.cs`,
built on the VM with `payload-stub/build-stub.ps1` (in-box C# compiler, no installs).
Step 1 is the custom atomic `atomics/T1059.001/T1059.001.yaml`, which downloads the
stub over the network and runs it; it lands at `%TEMP%\update-svc.exe`.

Hosting: put `stub.exe` where the VM can reach it over the network so the download is
real and `DeviceNetworkEvents` has it. An Azure Storage blob in the lab works (upload
by hand / portal, use a public-read container or a SAS URL). Then set `payload_url`
in the yaml. Do not commit `stub.exe` to the repo.

- Source of the harmless PE: self-compiled stub (`payload-stub/stub.cs`)
- Payload file name / path on disk: `%TEMP%\update-svc.exe` (`C:\Users\iradmin\AppData\Local\Temp`)
- SHA256: `8765F0FEE6655CAE983F7C1539D3E1CF2735C1C7951171A35FE54E1B140DE66E`
  (confirmed 2026-11-24: same value in DeviceFileEvents, DeviceProcessEvents and
  `Get-FileHash` on the landed file; this is the step-6 block indicator)
- Download URL (defanged): `hxxps://[storage-account][.]blob[.]core[.]windows[.]net/lab/stub[.]exe`
  (fetched with a short-lived user-delegation SAS; the SAS token is a credential and
  is not recorded here)

## Step 4 dump method - credential access, PREVENTED

Living-off-the-land only; mimikatz.exe is never dropped. Outcome on this VM (real run
2026-11-24): the LSASS dump was PREVENTED at process launch for BOTH LotL tools, so no
dump was produced and no successful credential access occurred. A prevented step is
still part of the attack chain and the same incident.

- Method(s) attempted:
  1. comsvcs.dll MiniDump (built-in LotL) - `Invoke-AtomicTest T1003.001 -TestNumbers 2`
  2. procdump -ma lsass.exe (Sysinternals, signed) - `Invoke-AtomicTest T1003.001 -TestNumbers 1`
     (tried as an alternate after reconnecting RDP; same symptom)
- Result: both returned `Access is denied` at `CreateProcess` (Invoke-Process.ps1:45).
  rundll32 / procdump never started -> neither appears in DeviceProcessEvents.
- Prevention control: Defender behavioural / command-line AV protection (block mode).
  NOT ASR (`AttackSurfaceReductionRules_Ids` was empty) and NOT device isolation (the
  device stayed online and RDP reconnected). Confirmed by `Get-MpThreatDetection`:
  ThreatID `2147793100`, 2026-11-24 06:02:43, ProcessName `Unknown`, Resource
  `CmdLine:...` - a command-line behaviour detection on the comsvcs dump command.
- Dump file written: none (prevented).
- Where the detection signal lives: the AV detection event / Defender alert, NOT a
  DeviceProcessEvents process line (the blocked process generated none). Hunt in
  DeviceEvents (`AntivirusDetection`) / AlertEvidence.
- Alert as it actually appeared in the Defender portal: `[placeholder - record title + severity]`

The step-4 tooling (`rundll32`, `comsvcs.dll`, signed `procdump`) is deliberately NOT
added to a block-by-hash indicator later - a PIR point: here the block was behavioural,
not hash-based. (Optional sanity check, does not change the result: confirm the shell
was elevated with
`([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)`;
the comsvcs block is already confirmed by the AV detection above regardless.)

## Incident correlation (result)

The four steps rolled up into ONE incident, confirmed in the Defender portal
2026-11-24. This is the end-to-end "one incident" outcome the lab is built to show.

- Incident: **ID 15 - "Hands-on keyboard attack was launched from a compromised
  account (attack disruption)"**
- Severity / status / priority: High / Active / **100 (top priority)**
- Categories (tags): Lateral Movement, Ransomware, Attack Disruption
- Counts: 18 alerts, 4 assets, 22 evidence, 45 activities
- First activity: Nov 24 2026 3:35:12 PM (portal TZ)

Two things the investigation must account for:

1. **This ID 15 is the same case that began as install-time noise.** The pre-run note
   above recorded ID 15 as "Multiple threat families ... Ransomware" from the 56
   quarantined library samples. MDE has since MERGED the real 4-step chain into it, so
   the 18 alerts are a MIX: the four chain alerts (step 1 encoded PS + download, step 2
   scheduled task `spawn`, step 3 new admin `T1136.001_Admin`, step 4 prevented
   credential dump) plus the install-library quarantine noise. Separate the two in the
   investigation; do not treat all 18 as the attack.
   - Chain alerts confirmed present in the Alerts list: `[placeholder - verify all 4]`

2. **Automatic Attack Disruption fired.** The incident carries the "Attack Disruption"
   tag and lists "Disruption actions taken" as a priority factor - MDE took an
   automatic containment action on its own (typically suspend the compromised account
   `iradmin` or isolate the device). This most likely explains the abrupt RDP drop
   seen earlier (revises the earlier "transient network" reading). This is a key
   response-phase fact: automated containment happened BEFORE any manual response.
   - Disruption action taken (what / when, from Activities): `[placeholder]`

Deeper investigation (splitting chain alerts from noise, building the timeline, blast
radius, manual containment) is the blue-team phase, not this attack-run log.

## Cleanup

- Cleanup run (UTC): `[placeholder]`
- Command: `.\run-chain.ps1 -Cleanup` (Atomic cleanup, reverse order)
- VM confirmed back to clean state: `[placeholder]`

## Candidate tests (not final - verify on the lab VM before filling the script)

Shortlist from reading the atomics on 2026-11-21. Confirm with
`Invoke-AtomicTest <T> -ShowDetailsBrief` on the VM; numbers shift between
versions, so do not copy them into run-chain.ps1 until checked.

| Step | Technique | Candidate | Why |
|------|-----------|-----------|-----|
| 1 | T1059.001 | **custom atomic** (authored in `simulation/atomics/`), not a stock number | verified 2026-11-24: no stock test drops a PE (see step-1 note); candidate #9 does not exist in this ART version |
| 2 | T1053.005 | #2 "Scheduled task Local" (`SCHTASKS /Create`) | cleanest local persistence; #1 / #4 are backups |
| 3 | T1136.001 | #8 "Create a new Windows admin user" | does `net user /add` + `net localgroup administrators /add` in one test |
| 4 | T1003.001 | #2 "comsvcs.dll" (LotL, built-in) | alt: #1/#9 procdump, #8 Out-Minidump.ps1; AVOID #6/#7/#10 (mimikatz/pypykatz) |

Step 1 note: verified on the VM 2026-11-24 with `Invoke-AtomicTest T1059.001
-ShowDetailsBrief` (22 tests). There is no test #9, and no stock test does
"encoded PowerShell -> download -> land a PE and run it": the download tests (#3
BloodHound, #8 mshta) run in memory or drop non-PE, and the encoded-command tests
(#14-#16) do not download. So step 1 is authored as a custom atomic under
`simulation/atomics/T1059.001/`: encoded PowerShell that does `IWR -OutFile` of a
harmless PE then runs it, covering encoded PS (T1059.001), the network download
(`DeviceNetworkEvents`) and a PE on disk whose SHA256 is the step-6 indicator, kept
in step 1. Run with `Invoke-AtomicTest -PathToAtomicsFolder`. See "Step 1 payload"
above for the three constraints on that PE.

## Open items (resolve in phase 1, before the run)

- [x] Pick the test numbers after checking real event names and fields
      (`DeviceProcessEvents` / `DeviceEvents`) - do not guess. Done: step 1 custom #1,
      step 2 #2 "Scheduled task Local", step 3 #8 "Create a new Windows admin user",
      step 4 #2 "comsvcs.dll" (attempted + prevented).
- [x] Confirm step 1's test drops a PE, not just a script. (2026-11-24: encoded PS,
      blob download and `update-svc.exe` landing+execution all confirmed in hunting.)
- [x] Confirm step 4 uses the LotL variant, not the mimikatz test. (2026-11-24:
      comsvcs #2 and procdump #1, both LotL; both PREVENTED at process launch by
      Defender behavioural protection. Recorded as a prevented credential-access
      attempt - the signal is the AV detection, not a DeviceProcessEvents line.)
