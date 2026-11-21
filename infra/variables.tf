locals {
  location = "australiaeast"
}

# All inputs are set in GitHub (repository variables and secrets) and reach
# Terraform as TF_VAR_* in the workflow. Nothing sensitive is written in a file.

variable "admin_password" {
  description = "Local administrator password for the lab VM. GitHub secret ADMIN_PASSWORD."
  type        = string
  sensitive   = true
}

variable "management_source_cidr" {
  description = "Owner's public IP as a /32. The only address allowed to reach RDP (3389) on the VM. GitHub secret MANAGEMENT_SOURCE_CIDR."
  type        = string
  # Hidden in plan output, which is posted to the PR job summary.
  sensitive = true
}
