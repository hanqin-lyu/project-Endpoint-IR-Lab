# Endpoint Intrusion Investigation Lab

One Windows Server in Azure with Microsoft Defender for Endpoint. I run a four-step
intrusion against it with Atomic Red Team, write my own detections, then investigate
it starting from the alert only and write it up as a client-facing post-incident report.

Status: the run is complete (attack 2026-11-24, response 2026-11-25). The lab was torn
down on 2026-11-25: the destroy workflow removed all 9 Terraform resources (the VM and
its Defender for Servers setting with it), and the evidence snapshot, which is outside
Terraform state, was deleted by hand.

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
  worked through its lifecycle (MTTA and MTTR ended up coming from the Defender
  incident; see Design notes)
- A post-incident report: summary, timeline, scope, containment, prevention, recommendations, IOCs, MITRE mapping

## Setup

- **Endpoint:** 1 Windows Server VM in Azure, RDP open to my IP only, deallocated when not in use
- **Telemetry:** Defender for Servers Plan 1 on that VM only, which onboards Defender for Endpoint
- **Hunting and detections:** advanced hunting and custom detection rules in the Defender portal.
  Raw events are not streamed to Sentinel, to keep ingestion cost at zero
- **Fallback:** if the Defender portal features are not available with this licence,
  Sysmon + Azure Monitor Agent into a new Log Analytics workspace
- **Deployment:** Terraform, same CI/CD design as my earlier projects

## Repository layout

```text
infra/          Terraform (lab VM, Defender for Servers setting)
simulation/     attack chain: run-chain.ps1, custom T1059.001 atomic, payload stub source,
                SETUP.md and the real run log (simulation-log.md)
detections/     4 KQL rules, verification and tuning notes (README.md)
investigation/  walkthrough, response record, baseline and post-attack live response,
                disk preservation, scope query (hunting/), screenshots
itsm/           ticket.md (field snapshot, measurement) and ServiceNow screenshots
report/         Post-Incident-Report-FIN042.md
```

## Results

All from the run on 2026-11-24 (attack) and 2026-11-25 (response). Details are in the
linked files.

- **Chain.** Steps 1–3 ran. Step 4 was blocked by Defender Antivirus twice (`comsvcs.dll`
  MiniDump, then ProcDump) before the process started, so no LSASS dump exists and the
  planned behavioural LSASS-access alert never fired. Step 1 raised no built-in alert.
  See [walkthrough](investigation/walkthrough.md).
- **Detections.** 4 custom rules, checked against the real events: rules 1–3 verified;
  rule 4 verified on branch B (ProcDump written to disk), branch A cannot be because the
  attack was blocked. One tuning record (rule 3: 4 incidents for one action → 1 alert).
  See [detections](detections/README.md).
- **Incident.** Defender incident 15 holds 26 alerts, one host in scope. Rules 2 and 4
  did not join it on their own; their 3 alerts were linked by hand. The scope hunt
  found no other device, but the tenant has only one onboarded device.
- **Response.** Disk snapshot for evidence, containment released for cleanup, payload
  SHA256 as a block-and-remediate indicator, then the task, the added account and the
  working folders removed and the cleanup verified in hunting. The indicator has limits:
  a dormant copy is only quarantined when read, and a copy restored from quarantine ran.
  See [response record](investigation/response.md).
- **Ticket.** ServiceNow INC0010004, raised after the response. See [ticket](itsm/ticket.md).
- **Response times** (incident 15, same definition as `project-Sentinel-SOC`, measured
  from the first chain alert): contain 13 min 27 s (automatic), acknowledge 29 h 13 min
  32 s, resolve 29 h 26 min 37 s. The incident stayed New through the whole response and
  was acknowledged only after cleanup, so acknowledge and resolve measure the queue, not
  the work.
- **Main findings** ([report](report/Post-Incident-Report-FIN042.md)): automatic user
  containment ended the open RDP session but did not stop a new sign-in 49 seconds
  later; the device was never isolated; credential theft was prevented by antivirus,
  not by containment.

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
  forensic completeness. In the real run the device was not isolated, during the
  incident or after. Only the automatic user containment ran. The report records this
  as a gap, and isolating on confirmation is its first recommendation.
- Step 4 in practice. Defender Antivirus blocked both LSASS attempts before the process
  started, so there was no LSASS handle access and the planned behavioural alert never
  fired. The second attempt used Microsoft's signed ProcDump, not a pure
  living-off-the-land path. The investigation started from the step 2 alert instead.
- MTTA and MTTR come from Defender incident 15, not from the ServiceNow ticket. The
  ticket was raised after the response, so its own times measure the paperwork. The
  ticket keeps the response record as work notes with the real times (`itsm/ticket.md`).
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
  Resolved). The plan was to take the real MTTA and MTTR from its timestamps, measured the
  same way as the Sentinel SOC baseline; this changed in the run (see the MTTA note below). Automatic alert-to-ticket creation is out of scope: it
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
- Automated remediation is set to "Semi - approval required for all folders" for the lab
  VM, through its own device group (`lab-edr-ir`, matched on the device name). The
  tenant default for ungrouped devices is Full, which would let automated investigation
  delete the payload or the scheduled task before I collect them. The other Semi levels
  only hold back system folders or non-temp folders, and the step-1 payload likely lands
  in a user or temp folder. With approval required for every folder, automated
  investigation still runs and proposes actions, and I approve or reject each one in the
  Action center; those decisions go into the walkthrough. The device group is set by hand
  in the Defender portal, not in Terraform.
