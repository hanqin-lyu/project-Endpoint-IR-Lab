# Endpoint Intrusion Investigation Lab

One Windows Server in Azure with Microsoft Defender for Endpoint. I run a four-step
intrusion against it with Atomic Red Team, write my own detections, then investigate
it starting from the alert only and write it up as a client-facing post-incident report.

Status: planning. Nothing is built yet.

> The client and case ID (IR-2026-FIN042) are fictional. All telemetry, timestamps and
> screenshots come from my own lab machine. No synthetic logs.

## Why

My earlier projects show I can build: identity governance, guardrails as code, and a
Sentinel SOC. SOC analyst roles ask for something else: investigating suspicious
behaviour on an endpoint, and writing a report someone else can act on. This project
practises those two things.

## The intrusion

| Step | Technique | MITRE ATT&CK | Main tables |
|------|-----------|--------------|-------------|
| 1 | Encoded PowerShell, download and execute | T1059.001 | `DeviceProcessEvents`, `DeviceNetworkEvents` |
| 2 | Scheduled task persistence | T1053.005 | `DeviceProcessEvents`, `DeviceEvents` |
| 3 | New local administrator account | T1136.001 | `DeviceEvents`, `DeviceProcessEvents` |
| 4 | LSASS memory dump with a living-off-the-land tool | T1003.001 | `DeviceEvents`, Defender alerts |

## Deliverables

- 4 detection rules (KQL), each with the tables and fields it uses and likely false positives
- At least one tuning record: what fired first, what changed, what fired after
- An investigation walkthrough, including the wrong turns
- Response on the host through Defender for Endpoint: isolate the device, collect an
  investigation package and review it (autoruns, scheduled tasks, processes, users and
  groups, network connections), then use live response to collect evidence (`getfile`,
  `processes`, `connections`) and remove persistence (`remediate`), with each command
  and its output logged
- Active prevention: turn the first-stage payload's SHA256 into a tenant-wide custom
  indicator (block and remediate) and verify a re-execution is blocked
- An ITSM ticket: one incident raised by hand in a free ServiceNow developer instance and
  worked through its lifecycle, the source of the real MTTA and MTTR figures
- A post-incident report: summary, timeline, scope, containment, prevention, recommendations, IOCs, MITRE mapping

## Setup

- **Endpoint:** 1 Windows Server VM in Azure, RDP open to my IP only, deallocated when not in use
- **Telemetry:** Defender for Servers Plan 1 on that VM only, which onboards Defender for Endpoint
- **Hunting and detections:** advanced hunting and custom detection rules in the Defender portal.
  Raw events are not streamed to Sentinel, to keep ingestion cost at zero
- **Fallback:** if the Defender portal features are not available with this licence,
  Sysmon + Azure Monitor Agent into a new Log Analytics workspace
- **Deployment:** Terraform, same CI/CD design as my earlier projects

## Repository layout (planned)

```text
infra/          Terraform
simulation/     run-chain.ps1 and the simulation log
detections/     KQL rules and tuning notes
investigation/  hunting queries and the walkthrough
itsm/           ticket field snapshot and ServiceNow lifecycle screenshots
report/         Post-Incident-Report-FIN042.md
```

## Results

[placeholder — filled in from real runs]

## Design notes

- Merged from two drafts: a set of isolated Atomic tests, and an M365 + endpoint attack
  chain. Kept the single-chain story and the real telemetry; dropped the M365 identity
  half (needs a test tenant), the synthetic log datasets, the `winword.exe` macro chain
  and C2 beaconing.
- Defender for Servers instead of Microsoft 365 E5: E5 user licences do not cover servers,
  and the identity and email parts of E5 are out of scope.
- Step 4 dumps LSASS with a living-off-the-land tool (for example `comsvcs.dll MiniDump`,
  `procdump`, or `MiniDumpWriteDump`) instead of dropping `mimikatz.exe`. Defender's static
  signature would likely quarantine mimikatz.exe before it touches LSASS, which tests the
  antivirus block, not behavioural detection. The LotL path leaves no known-bad binary on
  disk and triggers the behavioural alert on abnormal LSASS handle access (`PROCESS_VM_READ`)
  — the credential-theft signal the lab is built to investigate. The post-incident report
  takes this alert as its starting point.
- Multi-stage intrusion, one incident. A real attack advances in stages, so the chain is
  investigated as one incident, not four separate alerts. Defender XDR correlates alerts
  that share entities into a single incident and builds the attack story; the walkthrough
  records whether every step was pulled in automatically or an alert had to be linked by
  hand. This drives a detection requirement: each custom detection rule maps its impacted
  entities (device, account, file, process) so the alerts correlate. The attack story is
  done in the Defender portal; syncing incidents to Sentinel (free, no log ingestion) for
  its own attack story is a wave-2 upgrade.
- Response order on a confirmed intrusion: scope first (which host, which account, what
  ran), then isolate the device in Defender for Endpoint to stop lateral movement, then
  forensics and remediation. Once an intrusion is confirmed, containment comes before
  forensic completeness. The report's containment section records the isolation action
  and its time. [placeholder — isolation timestamp and the MDE "Isolate device" record
  from the real run.]
- From detection to active prevention. Isolation and remediation handle this one host;
  the investigation's payload hash is then promoted to a tenant-wide block-and-remediate
  custom indicator, so the file is blocked everywhere and existing copies are removed —
  intelligence from one incident becomes a standing control, not just another alert.
  Windows file indicators only match PE files (`.exe`/`.dll`), so the target is the
  first-stage payload, never the step-4 living-off-the-land tooling (`rundll32`,
  `comsvcs.dll`, signed `procdump`), which the report explains is deliberately not
  blocked by hash. Prerequisite (enabled in the lab tenant on purpose): Defender
  Antivirus in active mode with cloud protection, and "Allow or block file" turned on in
  Advanced features.
- ITSM ticketing is modelled by hand, not automated. One incident is raised in a free
  ServiceNow developer instance and walked through its lifecycle (New → In Progress →
  Resolved); its timestamps are where the real MTTA and MTTR come from, measured the same
  way as the Sentinel SOC baseline. Automatic alert-to-ticket creation is out of scope: it
  would need a log hub (Sentinel) to push alerts, which this project deliberately avoids to
  keep ingestion cost at zero. The ticket stays out of Terraform and CI.
- Defender for Servers Plan 1 is turned on for the lab VM only, at the resource level
  (`Microsoft.Security/pricings` on the VM, in Terraform), not for the subscription. Other
  machines in the subscription stay on Free and are not billed. The setting always exists
  on a VM (it reads back as the inherited Free tier), so Terraform updates it rather than
  creating it; `terraform destroy` deletes the VM and the setting with it. The
  subscription's existing Endpoint protection setting would install `MDE.Windows` on
  its own, but the first push can take up to 12 hours, so I installed the extension by
  hand with `az vm extension set`, using the onboarding package from Defender for
  Cloud's `mdeOnboardings` API. The extension is outside Terraform and goes with the VM
  on `terraform destroy`. It ships in its own
  PR because merging it starts the plan's 30-day trial, which cannot be paused.
