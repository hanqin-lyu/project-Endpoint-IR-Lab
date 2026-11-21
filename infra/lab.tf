# ---------------------------------------------------------------------------
# Resource group
# ---------------------------------------------------------------------------
# Created by hand, so the pipeline needs no subscription-level write access
# (same split as project-Sentinel-SOC). The budget alert on this group is also
# set up by hand. `terraform destroy` removes the resources inside it, not the
# group itself.
data "azurerm_resource_group" "lab" {
  name = "rg-endpoint-ir-lab"
}

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------
# Isolated network for the lab: one VNet, one subnet with the NSG on it, and a
# static public IP for RDP. Nothing is peered with any other network.
module "vnet" {
  source  = "Azure/avm-res-network-virtualnetwork/azurerm"
  version = "0.23.0"

  name             = "vnet-endpoint-ir"
  location         = local.location
  parent_id        = data.azurerm_resource_group.lab.id
  address_space    = ["10.20.0.0/16"]
  enable_telemetry = false

  subnets = {
    lab = {
      name             = "snet-endpoint-ir"
      address_prefixes = ["10.20.1.0/24"]
      # The NSG sits on the subnet, not the NIC, so all rules are in one place.
      network_security_group = {
        id = module.nsg.resource_id
      }
    }
  }
}

# Standard SKU blocks all inbound traffic unless an NSG rule allows it.
# Kept outside the VM module so the address survives a VM rebuild.
module "pip" {
  source  = "Azure/avm-res-network-publicipaddress/azurerm"
  version = "0.2.1"

  name                = "pip-endpoint-ir"
  location            = local.location
  resource_group_name = data.azurerm_resource_group.lab.name
  allocation_method   = "Static"
  sku                 = "Standard"
  enable_telemetry    = false
}

# ---------------------------------------------------------------------------
# NSG rules (lower number is checked first)
#   In  100   admin RDP on 3389, from the owner's IP only (separate resource below)
# Outbound is left at the Azure defaults: the VM must reach the Internet to
# onboard Defender for Endpoint, pull Invoke-AtomicRedTeam and download tools.
# There is no public listening port, unlike the honeypot in the Sentinel repo.
# ---------------------------------------------------------------------------
module "nsg" {
  source  = "Azure/avm-res-network-networksecuritygroup/azurerm"
  version = "0.6.0"

  name             = "nsg-endpoint-ir"
  location         = local.location
  parent_id        = data.azurerm_resource_group.lab.id
  enable_telemetry = false

  # RDP is a separate resource below: the module runs for_each over its rule
  # map, which cannot hold the sensitive management IP.
  security_rules = {}
}

# RDP for the owner only. The owner's IP is sensitive, so this is a separate
# resource rather than an entry in the module's rule map.
resource "azurerm_network_security_rule" "admin_rdp" {
  name                        = "Allow-Admin-RDP-From-Mgmt"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "3389"
  source_address_prefix       = var.management_source_cidr
  destination_address_prefix  = "*"
  resource_group_name         = data.azurerm_resource_group.lab.name
  network_security_group_name = module.nsg.name
}

# ---------------------------------------------------------------------------
# VM
# ---------------------------------------------------------------------------
# Windows Server 2022 with a local admin account. Defender for Endpoint (via
# Defender for Servers Plan 1) and Invoke-AtomicRedTeam are set up on the VM by
# hand, not in Terraform. 2022 is the minimum for MDE live response.
module "vm" {
  source  = "Azure/avm-res-compute-virtualmachine/azurerm"
  version = "0.21.0"

  name                = "vm-ir-lab-01"
  location            = local.location
  resource_group_name = data.azurerm_resource_group.lab.name
  os_type             = "Windows"
  # 2 vCPU, 4 GB. Enough to run the attack chain; the VM is deallocated when
  # not in use and the resource group is destroyed at the end.
  sku_size         = "Standard_B2s"
  enable_telemetry = false

  # One VM, no need to pin an availability zone.
  zone = null

  account_credentials = {
    admin_credentials = {
      username                           = "iradmin"
      password                           = var.admin_password
      generate_admin_password_or_ssh_key = false
    }
  }

  # System-assigned identity for the Azure built-in policies that onboard and
  # configure the VM. No role is assigned to it here.
  managed_identities = {
    system_assigned = true
  }

  # Off: it needs the EncryptionAtHost feature registered on the subscription,
  # and the lab disk holds nothing worth protecting. The platform still
  # encrypts the disk at rest.
  encryption_at_host_enabled = false

  os_disk = {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference = {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-datacenter-azure-edition"
    version   = "latest"
  }

  network_interfaces = {
    nic = {
      name = "nic-ir-lab"
      ip_configurations = {
        ipconfig = {
          name                          = "ipconfig-ir-lab"
          private_ip_subnet_resource_id = module.vnet.subnets["lab"].resource_id
          public_ip_address_resource_id = module.pip.resource_id
        }
      }
    }
  }

  # Serial console access if RDP breaks. Uses a managed storage account.
  boot_diagnostics = true
}

# ---------------------------------------------------------------------------
# Auto-shutdown
# ---------------------------------------------------------------------------
# Deallocates the VM every evening so a forgotten VM does not bill overnight.
# Compute billing stops while deallocated; start it again by hand before a run.
resource "azurerm_dev_test_global_vm_shutdown_schedule" "lab" {
  virtual_machine_id = module.vm.resource_id
  location           = local.location
  enabled            = true

  daily_recurrence_time = "1900"
  timezone              = "AUS Eastern Standard Time"

  notification_settings {
    enabled = false
  }
}
