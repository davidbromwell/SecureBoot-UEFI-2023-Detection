Detect-SecureBoot2023-CertStatus
Version: 2.3 | Author: David Bromwell / ACR | Status: Production Pilot Ready

A detection-only PowerShell script designed for use as an Intune Proactive Remediation detection script. It inventories the Windows UEFI CA 2023 Secure Boot certificate rollout status across managed endpoints — with no changes made to the device.

What It Does
Evaluates Secure Boot state via Confirm-SecureBootUEFI

Reads UEFICA2023Status, error codes, and available update flags from the registry

Scans UEFI db and kek variable content for the 2023 certificates

Checks the Secure-Boot-Update scheduled task state

Queries TPM-WMI event log for relevant event IDs including Event 1808

Classifies each device into a clear, human-readable state

Outputs a compact pipe-delimited or JSON string optimized for the Intune portal's 1,900-character limit

What It Does NOT Do
Does not remediate

Does not write registry values

Does not start the Secure-Boot-Update scheduled task

Does not reboot the device

Does not suspend or modify BitLocker

Requirements
Run As: SYSTEM

Deployment: Intune Proactive Remediation (Detection script)

Encoding: ASCII compatible

Detection States
| State                             | Meaning                                            |
| --------------------------------- | -------------------------------------------------- |
| Fully Updated                     | Secure Boot enabled + UEFICA2023Status = Updated   |
| Updated - Secure Boot Not Enabled | Status Updated but Secure Boot is off              |
| Error State                       | Non-zero error codes, update incomplete            |
| Secure Boot Disabled              | Disabled in firmware                               |
| Certs Present - Awaiting Update   | 2023 certs in UEFI, status not yet Updated         |
| In Progress                       | Update actively underway                           |
| Not Started                       | No status value found                              |
| Not Applicable - Legacy BIOS      | Non-UEFI device                                    |
| Needs Review                      | Partial or unrecognized state                      |
