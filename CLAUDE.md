# Project: Endpoint Intrusion Investigation Lab

A solo portfolio project. One Windows Server in Azure with Defender for Endpoint
(through Defender for Servers Plan 1). The owner runs a four-step Atomic Red Team
intrusion, writes detections, investigates from the alert only, and writes a
post-incident report. The focus is investigation and reporting, not building.
The owner reads every change as a diff in VS Code and commits it himself.

Status: planning. Nothing is built yet.

## Hard rules (do not break, even if asked in passing)

1. **Never commit, push, stage, reset, clean or rebase.** Edit files only. (Enforced by `.claude/settings.json` deny rules.)
2. **Never run `terraform apply`, `destroy`, `import`, `state` or `plan`.** Allowed locally: `terraform fmt`, `terraform init -backend=false`, `terraform validate`.
3. **No cloud changes.** Do not run `az login`, and do not run any `az` command that creates, updates or deletes anything. Read-only `show`/`list` is fine only if the owner is already logged in.
4. **No secrets.** Do not read or write `terraform.tfvars`, `*.tfstate`, `.env`, keys or `*.parameters.local.json`. Never put a subscription ID, tenant ID, key or real IP in a file.
5. **Never invent results.** Alerts, timestamps, query output and screenshots come from real runs. Until then use `[placeholders]`. No synthetic logs.
6. **Atomic Red Team commands go into scripts only.** The owner runs them on the lab VM.

## Keep it simple

- Scope is the four-step chain in the README. No M365 identity work, no SOAR, no C2.
- Every cost decision favours zero ingestion: raw events stay in Defender advanced hunting, not Sentinel.
- No variables, options or files "for later". If a value is not set by the owner, hard-code it.
- Terraform only covers the VM, network, auto-shutdown and budget alert.

## Writing

- Repo files are in English, short and plain. The owner writes to you in Chinese; reply in Chinese.
- In KQL, comment which tables and fields the query uses.
- Defang IPs and URLs in reports and notes (`203[.]0[.]113[.]10`, `hxxp://`).
- Record notable design changes in the README's Design notes.
