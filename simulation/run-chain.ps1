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

  Each step is pinned to an Atomic test by number. The numbers are left UNSET on
  purpose: choose them in phase 1 after checking the real telemetry (confirm the
  event names and join fields against DeviceProcessEvents / DeviceEvents first),
  then fill in $Steps below. The script refuses to run until every number is set.

  Step 1 MUST drop a PE payload (.exe / .dll). Its SHA256 becomes the block
  indicator in the response phase, so a .ps1-only test will not do. If the test
  you pick writes only a script, switch to one that drops a PE, or substitute a
  harmless stand-in PE.

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
        TestNumbers = $null   # [placeholder] cradle test #9, payload URL -> harmless PE (see note)
        Note        = @'
Entry point. Use download-cradle test #9 with its payload URL pointed at a HARMLESS
PE, so this step pulls an .exe over the network and lands it on disk. That PE's
SHA256 is the step-6 block-and-remediate indicator (kept in step 1). The PE must be
not-known-bad (blocked later only because we add its hash by hand), land on disk
(not memory-only), and come over a real network cradle. Details in simulation-log.md.
'@
    },
    @{
        Name        = '2. Scheduled task persistence'
        Technique   = 'T1053.005'
        Tables      = 'DeviceProcessEvents, DeviceEvents'
        TestNumbers = $null   # [placeholder]
        Note        = ''
    },
    @{
        Name        = '3. New local administrator account'
        Technique   = 'T1136.001'
        Tables      = 'DeviceEvents, DeviceProcessEvents'
        TestNumbers = $null   # [placeholder] create account AND add to Administrators
        Note        = 'Create the local account and add it to the Administrators group.'
    },
    @{
        Name        = '4. LSASS memory dump, living-off-the-land'
        Technique   = 'T1003.001'
        Tables      = 'DeviceEvents, Defender alerts'
        TestNumbers = $null   # [placeholder] pick the LotL variant, never the mimikatz one
        Note        = @'
LotL only, no mimikatz.exe on disk. Pick ONE and record it in the log:
  a) rundll32.exe comsvcs.dll, MiniDump <lsass_pid> dump.bin full   (built in)
  b) procdump -ma lsass.exe out.dmp                                 (Sysinternals, signed, dual-use)
  c) PowerShell calling MiniDumpWriteDump
Why LotL: mimikatz has a strong static signature and is quarantined before it
reads LSASS, so it only tests "AV blocked a known-bad file", not the behavioural
detection of abnormal LSASS handle access (PROCESS_VM_READ) - the credential-theft
signal this lab investigates, and where the PIR timeline starts. The step-4 tooling
(rundll32 / comsvcs.dll / procdump) is deliberately NOT blocked by hash later.
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
# ---------------------------------------------------------------------------

Assert-AtomicModule
Assert-TestNumbers

if ($Cleanup) {
    Write-Step 'Cleanup: running Atomic cleanup for every step, reverse order.'
    for ($i = $Steps.Count - 1; $i -ge 0; $i--) {
        $s = $Steps[$i]
        Write-Step "Cleanup $($s.Name) [$($s.Technique)]"
        Invoke-AtomicTest $s.Technique -TestNumbers $s.TestNumbers -Cleanup
    }
    Write-Step 'Cleanup done. Confirm the VM is back to a clean state before the next run.'
    return
}

if ($CheckPrereqs) {
    Write-Step 'Checking and installing prerequisites for every step.'
    foreach ($s in $Steps) {
        Write-Step "Prereqs $($s.Name) [$($s.Technique)]"
        Invoke-AtomicTest $s.Technique -TestNumbers $s.TestNumbers -GetPrereqs
    }
    Write-Step 'Prereq check done.'
    return
}

Write-Step 'Starting attack chain IR-2026-FIN042 (lab only).'
foreach ($s in $Steps) {
    Write-Step "START  $($s.Name) [$($s.Technique)]  tables: $($s.Tables)"
    Invoke-AtomicTest $s.Technique -TestNumbers $s.TestNumbers
    Write-Step "DONE   $($s.Name)"
}
Write-Step 'Chain complete. Record timestamps and screenshots in simulation-log.md.'
Write-Step 'Run with -Cleanup once the investigation has captured what it needs.'
