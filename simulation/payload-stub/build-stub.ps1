#Requires -Version 5.1
<#
  build-stub.ps1 - compile the harmless lab stub (stub.cs) into a PE.

  Owner runs this on the lab VM. Uses the in-box C# compiler through Add-Type, so
  nothing needs installing. Prints the SHA256 to record in simulation-log.md and to
  use as the step-6 block-and-remediate indicator.

  The stub is benign (see stub.cs). It is blocked later only because its hash is
  added to a custom indicator by hand.

  After building, host stub.exe somewhere the VM can reach over the network (so
  step 1 is a real download and DeviceNetworkEvents has the event), then set that
  URL as payload_url in atomics/T1059.001/T1059.001.yaml. An Azure Storage blob in
  the lab works; see the note in simulation-log.md.
#>

$ErrorActionPreference = 'Stop'

$src = Join-Path $PSScriptRoot 'stub.cs'
$out = Join-Path $PSScriptRoot 'stub.exe'

Add-Type -TypeDefinition (Get-Content -Raw -Path $src) `
    -OutputAssembly $out -OutputType ConsoleApplication

$hash = (Get-FileHash -Algorithm SHA256 -Path $out).Hash
Write-Host "Built:  $out"
Write-Host "SHA256: $hash"
Write-Host "Record the SHA256 in simulation-log.md (step 1 payload) and reuse it for the step-6 indicator."
