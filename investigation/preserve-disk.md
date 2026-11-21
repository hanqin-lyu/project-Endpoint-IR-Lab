# Preserve the disk (evidence snapshot)

Preservation only — not analysis. Takes a point-in-time snapshot of the VM's OS disk so
the on-disk state at the moment the investigation started is fixed and can be examined
later if needed. Offline disk analysis (attaching the snapshot read-only to a separate
forensic VM) is out of scope for this lab; this runbook stops at preserving.

**When.** Early, alongside or just before live-response collection. Order of volatility:
memory, processes and network connections are captured live because they are gone on
shutdown; the disk can be frozen as a snapshot now and read at leisure. Isolation does
not need to come first — a snapshot can be taken on a running or deallocated VM.

**Why a snapshot and not a full image.** A managed-disk snapshot freezes the disk state
without exporting it. Exporting the disk and hashing it for a formal chain of custody adds
egress cost and is the next step up; this lab records the snapshot's identity and time
instead.

**Not in Terraform.** This is an incident-time action, run by hand, like the Atomic tests
and the ServiceNow ticket. A snapshot made here is **not** in Terraform state, so
`terraform destroy` will not remove it — it must be deleted by hand at cleanup (see below),
or it keeps billing.

## Run (owner, from a workstation already signed in with `az login`)

```bash
# Resource group and VM from infra/ (not secrets). No subscription or tenant id here.
RG="rg-endpoint-ir-lab"
VM="vm-ir-lab-01"
SNAP="snap-ir-lab-01-evidence-$(date -u +%Y%m%dT%H%M%SZ)"

# 1. Resolve the OS managed-disk id.
OS_DISK_ID=$(az vm show -g "$RG" -n "$VM" \
  --query "storageProfile.osDisk.managedDisk.id" -o tsv)

# 2. Take an incremental snapshot (billed on used/delta size, Standard HDD rate).
az snapshot create -g "$RG" -n "$SNAP" --source "$OS_DISK_ID" --incremental true

# 3. Record the preservation evidence for the PIR appendix.
az snapshot show -g "$RG" -n "$SNAP" \
  --query "{id:id, created:timeCreated, source:creationData.sourceResourceId}" -o json
```

Paste the step-3 output into the PIR appendix: snapshot resource id, creation time (UTC)
and the source disk id are the preservation record.

## Cleanup (end of project, before/with teardown)

```bash
RG="rg-endpoint-ir-lab"
# List any evidence snapshots still present, then delete each by name.
az snapshot list -g "$RG" --query "[?starts_with(name,'snap-ir-lab-01-evidence-')].name" -o tsv
az snapshot delete -g "$RG" -n "<snapshot-name>"
```
