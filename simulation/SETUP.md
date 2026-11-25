# Simulation setup - running the attack chain

How to stage and run the chain for case IR-2026-FIN042. This is manual lab setup,
done by the owner on the lab VM. It is not in Terraform and not run by CI or any
assistant, the same split as Defender onboarding.

## Where it runs: local, on the lab VM only

- Install and run Atomic Red Team on `vm-ir-lab-01` only. Not on the owner's Mac
  (the atomics are Windows commands), and nowhere else.
- Run the chain **locally** on the VM (RDP in, run the script), not with Atomic's
  remote `-Session` mode. Decided on purpose:
  - One target, no fleet to orchestrate - remote execution's only real advantage
    does not apply.
  - Remote needs WinRM (5985/5986) open and a separate Windows control host; the
    NSG only opens RDP 3389 to the owner IP, and a control host costs more.
  - The scenario is a stolen identity acting **on the host**. Local execution keeps
    a clean `DeviceProcessEvents` parent-child tree; remote execution injects
    `wsmprovhost.exe` / WinRM and remote-logon artifacts that muddy the timeline
    and blur local vs. lateral movement, which is not what this lab investigates.
- Remote mode would only be better for validating many endpoints at once, or for
  deliberately generating lateral-movement telemetry - neither is in scope here.

## Order

1. Infra applied, VM running, RDP reachable from the owner IP.
2. Defender for Servers Plan 1 enabled and MDE onboarding complete on the VM
   (first onboarding can take up to ~12h).
3. Then install Atomic Red Team and run the chain.

## Install Atomic Red Team (on the VM, elevated PowerShell)

Pulls the execution framework (Invoke-AtomicRedTeam) and the atomics content.

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); Install-AtomicRedTeam -getAtomics
```

```powershell
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

Verify it loaded:

```powershell
Invoke-AtomicTest T1053.005 -ShowDetailsBrief
```

## Defender interaction (expected, not a fault)

- ART is a known offensive toolset. Defender may alert on or quarantine parts of
  the install or some payloads. That is a signal, not a failure - the point of the
  lab is for Defender to see the activity.
- Do not disable Defender. If a specific step cannot stage its payload because the
  tool binary is quarantined, the usual move is a temporary AV exclusion on the
  `ExternalPayloads` folder to stage the tool, then rely on behavioural detection
  of the run. Treat that as a tuning decision made per step, recorded in
  `simulation-log.md` - never a blanket AV-off.
- This chain avoids mimikatz for step 4 for exactly this reason (see the step-4
  note in `run-chain.ps1`).

## How to run: validate by hand first, then reproduce with the script

Two phases. Do not fill `run-chain.ps1` until phase 1 passes.

### Phase 1 - manual validation, one step at a time

For each candidate test (see the list in `simulation-log.md`): run it by hand,
confirm it does what we need and that Defender raises the expected alert, take the
screenshots, record it, then clean that one test up before the next.

```powershell
Invoke-AtomicTest T1136.001 -TestNumbers 8 -GetPrereqs   # stage prereqs
Invoke-AtomicTest T1136.001 -TestNumbers 8               # run it
# ... check the Defender alert, screenshot, note the real event names/fields
Invoke-AtomicTest T1136.001 -TestNumbers 8 -Cleanup      # reset before the next test
```

Per step, confirm and write to `simulation-log.md`: the final test number, the
timestamp, the exact command, the screenshot, and the alert as it actually
appeared. Step 1: confirm a PE lands and record its SHA256. Step 4: confirm the
LotL method and its alert.

### Phase 2 - scripted reproduction

Once all four are validated, put the confirmed numbers into `run-chain.ps1`
(`$Steps[].TestNumbers`), then run the whole chain in order for one clean,
timestamped reproduction - this is the run the investigation and PIR timeline
are built from.

```powershell
.\run-chain.ps1 -CheckPrereqs   # stage prerequisites for each step
.\run-chain.ps1                 # run steps 1 -> 2 -> 3 -> 4 in order
.\run-chain.ps1 -Cleanup        # Atomic cleanup, reverse order, once the investigation has what it needs
```

## Step 1 payload (block indicator)

Step 1 uses a T1059.001 download-cradle test (candidate #9) with its payload URL
pointed at a **harmless PE**, so step 1 pulls an `.exe` over the network and lands
it on disk. That PE's SHA256 becomes the step-6 block-and-remediate indicator; the
indicator stays in step 1. Prepare the PE before the run, and keep it:

1. Not known-bad - its own hash must not trip AV on its own (self-compiled benign
   stub, or a renamed signed-but-harmless EXE). It is blocked later only because we
   add its hash to the indicator by hand; that is what the demo shows.
2. Landed on disk, not memory-only, so there is a hash to block and a file to
   `remediate`.
3. Fetched by a real network download cradle, not a local copy, so
   `DeviceNetworkEvents` records the download.

Record the file name, SHA256, defanged URL and the PE's source in
`simulation-log.md`.

## Hard rules

- Owner runs everything here by hand on the lab VM, with a lab account. No CI, no
  assistant, no real users, data or external targets.
- Files only in `simulation/`. Nothing here goes into Terraform.
- Never invent results; use `[placeholder]` until a real run fills them.
