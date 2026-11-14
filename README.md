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
| 4 | LSASS memory access attempt (expected to be blocked) | T1003.001 | `DeviceEvents`, Defender alerts |

## Deliverables

- 4 detection rules (KQL), each with the tables and fields it uses and likely false positives
- At least one tuning record: what fired first, what changed, what fired after
- An investigation walkthrough, including the wrong turns
- A post-incident report: summary, timeline, scope, containment, recommendations, IOCs, MITRE mapping

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
