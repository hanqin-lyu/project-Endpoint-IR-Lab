# Simulation log - IR-2026-FIN042 (fictional case, real lab telemetry)

One run of the four-step chain against the lab VM. Fill this in as the run goes:
one row per step with the Atomic test number used, the start time, the exact
command, and the screenshot. All values come from the real run - leave
`[placeholder]` until then, do not guess.

- Run by: owner, by hand on the lab VM, lab account only.
- VM: `vm-ir-lab-01`
- Run date (UTC): `[placeholder]`
- Invoke-AtomicRedTeam version: `[placeholder]`

## Steps

| # | Technique | Atomic test | Start time (UTC) | Command (as run) | Screenshot |
|---|-----------|-------------|------------------|------------------|------------|
| 1 | T1059.001 - Encoded PowerShell, download and execute | `[placeholder]` | `[placeholder]` | `[placeholder]` | `[placeholder]` |
| 2 | T1053.005 - Scheduled task persistence | `[placeholder]` | `[placeholder]` | `[placeholder]` | `[placeholder]` |
| 3 | T1136.001 - New local administrator account | `[placeholder]` | `[placeholder]` | `[placeholder]` | `[placeholder]` |
| 4 | T1003.001 - LSASS dump (living-off-the-land) | `[placeholder]` | `[placeholder]` | `[placeholder]` | `[placeholder]` |

## Step 1 payload (for the block indicator)

Step 1 must drop a PE (`.exe` / `.dll`). Its SHA256 is promoted to a
block-and-remediate custom indicator in the response phase.

Decided (edr mainline): use a T1059.001 download-cradle test (candidate #9) with
its payload URL pointed at a **harmless PE**, so step 1 really pulls an `.exe` over
the network and lands it on disk. That PE's SHA256 is the step-6 block indicator.
The indicator stays in step 1 - it is not moved to another step. This is inside
the approved design (plan doc S7.5 pre-authorised picking a test that drops a PE).

Three constraints for the harmless PE:
1. Not known-bad. Its own hash must not trip AV on its own (e.g. a self-compiled
   benign stub, or a renamed signed-but-harmless EXE). It must be blocked LATER
   only because we add its hash to the custom indicator by hand - that is what the
   block-indicator demo is showing. A file AV already flags defeats the point.
2. Lands on disk, not memory-only. No disk file means no hash to block and nothing
   for `remediate` to delete.
3. A real network download cradle, not a local copy, so `DeviceNetworkEvents` has
   the download and matches the tables noted for step 1.

- Payload file name / path on disk: `[placeholder]`
- SHA256: `[placeholder]`
- Download URL (defanged): `[placeholder, e.g. hxxp://203[.]0[.]113[.]10/payload.exe]`
- Source of the harmless PE (self-compiled stub / renamed signed EXE): `[placeholder]`

## Step 4 dump method

Living-off-the-land only; mimikatz.exe is never dropped. Record the one method used:

- Method used (comsvcs MiniDump / procdump / MiniDumpWriteDump): `[placeholder]`
- Full command: `[placeholder]`
- Dump file written: `[placeholder]`
- Expected MDE alert (behavioural, abnormal LSASS handle access / `PROCESS_VM_READ`): `[placeholder]`
- Alert as it actually appeared in the Defender portal: `[placeholder]`

The step-4 tooling (`rundll32`, `comsvcs.dll`, signed `procdump`) is deliberately
NOT blocked by hash later - this is a point the post-incident report makes.

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
| 1 | T1059.001 | download-cradle **#9**, payload URL pointed at a harmless PE | decided: see "Step 1 payload" above for the three constraints |
| 2 | T1053.005 | #2 "Scheduled task Local" (`SCHTASKS /Create`) | cleanest local persistence; #1 / #4 are backups |
| 3 | T1136.001 | #8 "Create a new Windows admin user" | does `net user /add` + `net localgroup administrators /add` in one test |
| 4 | T1003.001 | #2 "comsvcs.dll" (LotL, built-in) | alt: #1/#9 procdump, #8 Out-Minidump.ps1; AVOID #6/#7/#10 (mimikatz/pypykatz) |

Step 1 note: every stock T1059.001 download test lands a `.ps1` or runs in memory,
not a PE. Decided (edr mainline): use cradle test #9 with its payload URL pointed at
a harmless PE so step 1 lands an `.exe` on disk; its SHA256 is the step-6 indicator,
kept in step 1. See "Step 1 payload" above for the three constraints on that PE.

## Open items (resolve in phase 1, before the run)

- [ ] Pick the four Atomic test numbers after checking real event names and fields
      (`DeviceProcessEvents` / `DeviceEvents`) - do not guess them.
- [ ] Confirm step 1's test drops a PE, not just a script.
- [ ] Confirm step 4 uses the LotL variant, not the mimikatz test.
