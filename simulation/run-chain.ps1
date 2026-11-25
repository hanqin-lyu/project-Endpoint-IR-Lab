#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
  run-chain.ps1 - Endpoint IR Lab attack chain (case IR-2026-FIN042, fictional)

  Runs a four-step intrusion against THIS lab VM only, in order, with
  Invoke-AtomicRedTeam. For the lab owner to run by hand on the lab machine,
  signed in with a lab account. Never run from CI, and never by an assistant.
  Lab resources only: no real users, no real data, no external targets.

  Prerequisite:
    Invoke-AtomicRedTeam installed and imported, atomics folder present.
    https://github.com/redcanaryco/invoke-atomicredteam

  Steps 2-4 are pinned to library Atomic tests by number, left UNSET on purpose:
  choose them in phase 1 after checking the real telemetry (confirm the event names
  and join fields against DeviceProcessEvents / DeviceEvents first), then fill in
  $Steps below. The script refuses to run until every number is set.

  Step 1 is a custom atomic authored in this repo (.\atomics\T1059.001), because no
  stock T1059.001 test does encoded-PowerShell -> download -> land a PE and run it.
  It drops a HARMLESS stub PE whose SHA256 becomes the block indicator in the
  response phase. Before the first run:
    1. Build the stub:  .\payload-stub\build-stub.ps1   (prints its SHA256)
    2. Host stub.exe where the VM can reach it over the network.
    3. Set payload_url in .\atomics\T1059.001\T1059.001.yaml to that URL.
  Copy this whole simulation\ folder to the VM so .\atomics and .\payload-stub come
  with the script.

  Step 4 dumps LSASS with a living-off-the-land tool, never mimikatz.exe (see the
  note on the step below). Record which method you used in simulation-log.md.

  Usage (on the lab VM, elevated PowerShell):
    .\run-chain.ps1 -CheckPrereqs   # install/verify each test's prerequisites
    .\run-chain.ps1                 # run steps 1 -> 2 -> 3 -> 4 in order
    .\run-chain.ps1 -Cleanup        # run Atomic cleanup for every step, reverse order

  After a run, fill in simulation-log.md (test number, timestamp, command,
  screenshot per step; step 4: dump method and the MDE alert it raised).
#>

[CmdletBinding()]
param(
    [switch]$CheckPrereqs,
    [switch]$Cleanup
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Steps. Fill TestNumbers after the phase-1 telemetry check. Leave as $null
# until then - the guard below stops the script while any are unset.
# TestNumbers is an int array so a step can chain more than one Atomic test.
# ---------------------------------------------------------------------------
$Steps = @(
    @{
        Name        = '1. Encoded PowerShell, download and execute'
        Technique   = 'T1059.001'
        Tables      = 'DeviceProcessEvents, DeviceNetworkEvents'
        TestNumbers = @(1)                              # custom test, authored in .\atomics
        AtomicsPath = (Join-Path $PSScriptRoot 'atomics')
        Note        = @'
Entry point. Custom atomic (.\atomics\T1059.001\T1059.001.yaml), not a stock number:
no stock T1059.001 test does encoded-PowerShell -> download -> land a PE and run it.
It downloads a HARMLESS stub PE (payload-stub\stub.cs, built by payload-stub\
build-stub.ps1) over the network and runs it. Before running: build the stub, host
it where the VM can reach it, and set payload_url in the yaml. The stub's SHA256 is
the step-6 block-and-remediate indicator (kept in step 1). Details in simulation-log.md.
'@
    },
    @{
        Name        = '2. Scheduled task persistence'
        Technique   = 'T1053.005'
        Tables      = 'DeviceProcessEvents, DeviceEvents'
        TestNumbers = @(2)    # #2 "Scheduled task Local", verified 2026-11-24 (task "spawn")
        Note        = ''
    },
    @{
        Name        = '3. New local administrator account'
        Technique   = 'T1136.001'
        Tables      = 'DeviceEvents, DeviceProcessEvents'
        TestNumbers = @(8)    # #8 "Create a new Windows admin user", verified 2026-11-24 (account T1136.001_Admin)
        Note        = 'Create the local account and add it to the Administrators group.'
    },
    @{
        Name        = '4. LSASS memory dump, living-off-the-land'
        Technique   = 'T1003.001'
        Tables      = 'DeviceEvents, Defender alerts'
        TestNumbers = @(2)    # #2 "comsvcs.dll" LotL, verified 2026-11-24 - PREVENTED at launch (see note + log)
        Note        = @'
Credential-access stage, LotL only, no mimikatz.exe on disk.
Real outcome on this VM (2026-11-24): the LSASS dump is PREVENTED at process launch.
Both #2 comsvcs.dll (built-in) and #1 procdump (signed) returned "Access is denied"
at CreateProcess, so rundll32 / procdump never ran and no dump was produced. This is
the RECORDED result: credential theft ATTEMPTED and PREVENTED - a prevented step is
still part of the chain and the same incident, not a missing step.
Blocker: Defender behavioural / command-line AV protection in block mode. NOT ASR
(rules empty) and NOT isolation (device stayed online). Confirmed by
Get-MpThreatDetection: ThreatID 2147793100, command-line behaviour detection on the
comsvcs dump command.
Detection signal lives in the AV detection / Defender alert, NOT DeviceProcessEvents
(the blocked process generated no process line). Expected on re-run: "Access is
denied" - that is the result, not a failure.
Why LotL, not mimikatz: mimikatz is a known-bad FILE quarantined on disk (only tests
"AV blocked a known file"); comsvcs/procdump are built-in/signed, so the block here
is behavioural credential-theft prevention - the stronger result. The step-4 tooling
is deliberately never added to a block-by-hash indicator later (a PIR point).
'@
    }
)

# ---------------------------------------------------------------------------
function Write-Step {
    param([string]$Message)
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
    Write-Host "[$ts] $Message"
}

function Assert-TestNumbers {
    $unset = $Steps | Where-Object { -not $_.TestNumbers }
    if ($unset) {
        Write-Error (
            "Atomic test numbers are not set yet. Fill TestNumbers for: " +
            (($unset | ForEach-Object { $_.Technique }) -join ', ') +
            ". Choose them after the phase-1 telemetry check, then re-run."
        )
        exit 1
    }
}

function Assert-AtomicModule {
    if (-not (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue)) {
        Write-Error 'Invoke-AtomicTest not found. Install and import Invoke-AtomicRedTeam first.'
        exit 1
    }
}

# Splat for Invoke-AtomicTest. A step may carry AtomicsPath to run a custom atomic
# from this repo (step 1) instead of the default library folder.
function Get-AtomicArgs {
    param([hashtable]$Step)
    $a = @{ TestNumbers = $Step.TestNumbers }
    if ($Step.AtomicsPath) { $a['PathToAtomicsFolder'] = $Step.AtomicsPath }
    return $a
}
# ---------------------------------------------------------------------------

Assert-AtomicModule
Assert-TestNumbers

if ($Cleanup) {
    Write-Step 'Cleanup: running Atomic cleanup for every step, reverse order.'
    for ($i = $Steps.Count - 1; $i -ge 0; $i--) {
        $s = $Steps[$i]
        Write-Step "Cleanup $($s.Name) [$($s.Technique)]"
        $a = Get-AtomicArgs $s
        Invoke-AtomicTest $s.Technique @a -Cleanup
    }
    Write-Step 'Cleanup done. Confirm the VM is back to a clean state before the next run.'
    return
}

if ($CheckPrereqs) {
    Write-Step 'Checking and installing prerequisites for every step.'
    foreach ($s in $Steps) {
        Write-Step "Prereqs $($s.Name) [$($s.Technique)]"
        $a = Get-AtomicArgs $s
        Invoke-AtomicTest $s.Technique @a -GetPrereqs
    }
    Write-Step 'Prereq check done.'
    return
}

Write-Step 'Starting attack chain IR-2026-FIN042 (lab only).'
foreach ($s in $Steps) {
    Write-Step "START  $($s.Name) [$($s.Technique)]  tables: $($s.Tables)"
    $a = Get-AtomicArgs $s
    Invoke-AtomicTest $s.Technique @a
    Write-Step "DONE   $($s.Name)"
}
Write-Step 'Chain complete. Record timestamps and screenshots in simulation-log.md.'
Write-Step 'Run with -Cleanup once the investigation has captured what it needs.'
