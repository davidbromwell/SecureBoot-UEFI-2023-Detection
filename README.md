# Secure Boot 2023 Certificate Status Detection

A PowerShell detection script designed for **Microsoft Intune
Remediations** (formerly Proactive Remediations) that inventories the
deployment status of Microsoft's 2023 Secure Boot certificate update
across Windows endpoints.

This script is **detection only**. It performs **no remediation**,
registry modifications, scheduled task execution, BitLocker operations,
firmware changes, or device restarts.

------------------------------------------------------------------------

## Features

-   Detection-only operation
-   PowerShell 5.1 compatible
-   ASCII encoded
-   Microsoft Intune Remediations ready
-   Compact output optimized for the Intune portal
-   Detailed local logging
-   Extensive error handling

The script evaluates:

-   Secure Boot state
-   UEFI firmware status
-   Microsoft Secure Boot servicing registry values
-   Secure Boot certificate presence in DB and KEK
-   Secure-Boot-Update scheduled task
-   TPM-WMI Secure Boot events
-   AvailableUpdates servicing state
-   Microsoft-defined deployment status values

------------------------------------------------------------------------

## Compliance Logic

A device is considered compliant when:

-   Secure Boot is enabled
-   `UEFICA2023Status = Updated`

Supporting signals such as certificate presence, scheduled task state,
TPM-WMI events, and registry values are collected for troubleshooting
but are **not** used as the primary compliance decision.

------------------------------------------------------------------------

## Output

The script provides:

-   Device state
-   Compliance result
-   Detection timestamp
-   Secure Boot evaluation
-   Certificate presence
-   Registry status
-   AvailableUpdates value
-   Scheduled task state
-   TPM-WMI event summary
-   Advisory information

The output is automatically compressed if necessary to remain within
Microsoft Intune portal limits.

------------------------------------------------------------------------

## Requirements

-   Windows PowerShell 5.1 or later
-   Windows 11 or supported Windows 10 versions
-   UEFI firmware
-   Microsoft Intune Remediations (optional)
-   Administrative or SYSTEM context

------------------------------------------------------------------------

## Logging

By default the script writes logs to:

``` text
C:\ProgramData\YourOrganization\Logs\SecureBootUEFICA2023
```

Replace **YourOrganization** with your preferred organization name or
another neutral folder name before deployment.

------------------------------------------------------------------------

## Environment-Specific Values

Before using this script, review any values that are specific to your
environment, including:

-   Log directory
-   Deployment method
-   Intune assignment scope
-   Execution context
-   Reporting requirements

This public version intentionally contains:

-   No company names
-   No internal domains
-   No tenant IDs
-   No device names
-   No group names
-   No user information

------------------------------------------------------------------------

## Example Usage

Run locally:

``` powershell
.\Detect-SecureBoot2023-CertStatus-v2.3.ps1
```

Deploy through:

-   Microsoft Intune Remediations
-   Microsoft Configuration Manager
-   Scheduled Tasks
-   Remote management platforms

------------------------------------------------------------------------

## Technologies Used

-   PowerShell
-   Microsoft Intune
-   Microsoft Graph (deployment integration)
-   Windows Security
-   Secure Boot
-   UEFI
-   TPM-WMI
-   Windows Registry
-   Windows Scheduled Tasks

------------------------------------------------------------------------

## Disclaimer

This project is provided as an example of enterprise endpoint
engineering.

Always validate the script in a test environment before deploying to
production. Review Microsoft's current Secure Boot guidance to ensure
deployment aligns with the latest supported servicing model.
