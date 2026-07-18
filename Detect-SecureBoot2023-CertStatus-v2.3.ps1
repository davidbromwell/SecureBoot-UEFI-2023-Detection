<#
.SYNOPSIS
    Detect-only Intune Proactive Remediation - Secure Boot 2023 Certificate Status

.DESCRIPTION
    Detection-only script for inventorying Secure Boot 2023 certificate rollout.
    Primary compliant signal for Intune:
      - Secure Boot can be evaluated as Enabled
      - UEFICA2023Status = Updated

    Important:
      - This script does not remediate.
      - This script does not write registry values.
      - This script does not start the Secure-Boot-Update scheduled task.
      - This script does not reboot the device.
      - This script does not suspend or modify BitLocker.

.NOTES
    Script Name    : Detect-SecureBoot2023-CertStatus.ps1
    Version        : 2.3
    Author         : David Bromwell
    Purpose        : Detection Only - Intune PAR inventory
    Run As         : SYSTEM
    Encoding       : ASCII compatible
    Status         : Production Pilot Ready

#>

# ====================== CONFIGURATION ======================
$ScriptVersion = "2.3"
# UPDATE "YourOrganization" to your preferred organization or neutral folder name.
$LogDirectory = "C:\ProgramData\YourOrganization\Logs\SecureBootUEFICA2023"
$LogPath = Join-Path -Path $LogDirectory -ChildPath "Detect-SecureBoot2023-CertStatus.log"

$OutputFormat = "Pipe" # Pipe or Json
$MaxPortalOutputLength = 1900
$MaxReasonLength = 400
# ===========================================================

function Initialize-Log {
    try {
        if (-not (Test-Path -LiteralPath $LogDirectory)) {
            New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
        }

        if ((Test-Path -LiteralPath $LogPath) -and ((Get-Item -LiteralPath $LogPath).Length -gt 512KB)) {
            Rename-Item -LiteralPath $LogPath -NewName "$LogPath.old" -Force -ErrorAction SilentlyContinue
        }
    }
    catch {}
}

function Write-Log {
    param([string]$Message)

    try {
        "$((Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) - $Message" |
            Add-Content -Path $LogPath -Force -ErrorAction SilentlyContinue
    }
    catch {}
}

function Get-RegValueSafe {
    param(
        [string]$Path,
        [string]$Name
    )

    try {
        return Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop
    }
    catch {
        return $null
    }
}

function Convert-ToHexString {
    param([object]$Value)

    if ($null -eq $Value) {
        return $null
    }

    try {
        return ("0x{0:X4}" -f [UInt64]$Value)
    }
    catch {
        return [string]$Value
    }
}

function Test-RealNonZeroValue {
    param([object]$Value)

    if ($null -eq $Value) {
        return $false
    }

    try {
        if ([int64]$Value -ne 0) {
            return $true
        }
        return $false
    }
    catch {
        $StringValue = [string]$Value
        if ([string]::IsNullOrWhiteSpace($StringValue)) {
            return $false
        }
        if ($StringValue -match '^\s*0+\s*$') {
            return $false
        }
        return $true
    }
}

function Get-FirmwareTypeSafe {
    $FirmwareType = $null

    try {
        $FirmwareType = $env:firmware_type
    }
    catch {}

    if ([string]::IsNullOrWhiteSpace($FirmwareType)) {
        $FirmwareType = "Unknown"
    }

    return $FirmwareType
}

function Get-SecureBootEvalState {
    try {
        $Enabled = Confirm-SecureBootUEFI -ErrorAction Stop

        return [pscustomobject]@{
            Enabled   = $Enabled
            EvalState = if ($Enabled) { "Enabled" } else { "Disabled" }
            EvalError = $null
        }
    }
    catch {
        return [pscustomobject]@{
            Enabled   = $null
            EvalState = "UnableToEvaluate"
            EvalError = $_.Exception.Message
        }
    }
}

function Get-SecureBootVariableText {
    param([string]$Name)

    try {
        $Variable = Get-SecureBootUEFI -Name $Name -ErrorAction Stop

        if ($Variable.Bytes) {
            return [System.Text.Encoding]::ASCII.GetString($Variable.Bytes)
        }
    }
    catch {}

    return ""
}

function Get-ScheduledTaskStateSafe {
    try {
        $Task = Get-ScheduledTask -TaskPath "\Microsoft\Windows\PI\" -TaskName "Secure-Boot-Update" -ErrorAction Stop
        return [pscustomobject]@{
            Exists = $true
            State  = [string]$Task.State
        }
    }
    catch {
        return [pscustomobject]@{
            Exists = $false
            State  = "Missing"
        }
    }
}

function Get-TpmWmiEventSummary {
    $EventIds = @(1036,1043,1044,1045,1796,1797,1798,1799,1800,1801,1803,1808)

    $Summary = [ordered]@{
        LatestTpmWmiEventId   = $null
        LatestTpmWmiEventTime = $null
        Event1808Seen         = $false
        Latest1808Time        = $null
        Event1808Count        = 0
    }

    try {
        $Events = Get-WinEvent -FilterHashtable @{
            LogName      = "System"
            ProviderName = "Microsoft-Windows-TPM-WMI"
            Id           = $EventIds
        } -MaxEvents 100 -ErrorAction Stop

        if ($Events) {
            $Latest = $Events | Sort-Object TimeCreated -Descending | Select-Object -First 1
            $Summary.LatestTpmWmiEventId = [int]$Latest.Id
            $Summary.LatestTpmWmiEventTime = $Latest.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")

            $Events1808 = $Events | Where-Object { $_.Id -eq 1808 } | Sort-Object TimeCreated -Descending
            if ($Events1808) {
                $Summary.Event1808Seen = $true
                $Summary.Event1808Count = @($Events1808).Count
                $Summary.Latest1808Time = ($Events1808 | Select-Object -First 1).TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            }
        }
    }
    catch {}

    return [pscustomobject]$Summary
}

function Convert-ToPortalText {
    param([object]$Result)

    function Format-PortalValue {
        param([object]$Value)

        if ($null -eq $Value) {
            return "null"
        }

        $Text = [string]$Value
        $Text = $Text -replace "`r|`n", " "
        $Text = $Text -replace "\|", "/"

        if ($Text.Length -gt 260) {
            $Text = $Text.Substring(0,260) + "..."
        }

        return $Text
    }

    $PortalFields = [ordered]@{
        V      = $Result.ScriptVersion
        Device = $Result.DeviceName
        Exit   = $Result.ExitCode
        State  = $Result.State
        Reason = $Result.Reason
        SB     = $Result.SecureBootEvalState
        Status = $Result.UEFICA2023Status
        Cap    = $Result.WindowsUEFICA2023Capable
        Err    = $Result.UEFICA2023Error
        ErrEvt = $Result.UEFICA2023ErrorEvent
        DB2023 = $Result.CertInActiveDB
        KEK23  = $Result.CertInKEK
        AU     = $Result.AvailableUpdates
        FW     = $Result.FirmwareType
        Task   = "$($Result.SecureBootUpdateTaskExists)/$($Result.SecureBootUpdateTaskState)"
        Evt    = $Result.LatestTpmWmiEventId
        E1808  = $Result.Event1808Seen
        L1808  = $Result.Latest1808Time
    }

    $Pairs = foreach ($Key in $PortalFields.Keys) {
        $FormattedValue = Format-PortalValue -Value $PortalFields[$Key]
        "$Key=$FormattedValue"
    }

    return ($Pairs -join " | ")
}

Initialize-Log
Write-Log "=== Secure Boot 2023 Detection Started (v$ScriptVersion) ==="

$ExitCode = 1
$State = "Unknown"
$Reason = "Detection did not complete"

try {
    # Default values for early-exit paths
    $SecureBootEval = [pscustomobject]@{ Enabled = $null; EvalState = "NotEvaluated"; EvalError = $null }
    $UEFICA2023Status = $null
    $Capable = $null
    $ErrorCode = $null
    $ErrorEvent = $null
    $CertInDB = $false
    $CertInKEK = $false
    $TaskInfo = [pscustomobject]@{ Exists = $false; State = "NotEvaluated" }
    $AvailableUpdatesHex = $null
    $EventSummary = Get-TpmWmiEventSummary

    $FirmwareType = Get-FirmwareTypeSafe
    $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $ComputerModel = $ComputerSystem.Model
    $Manufacturer = $ComputerSystem.Manufacturer

    $IsConfirmedLegacy = ($FirmwareType -match '^(BIOS|Legacy)$')

    if ($IsConfirmedLegacy) {
        $State = "Not Applicable - Legacy BIOS"
        $Reason = "Device is confirmed as non-UEFI firmware. Secure Boot certificate update is not applicable."
        $ExitCode = 0
    }
    else {
        $SecureBootEval = Get-SecureBootEvalState

        $ServicingPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
        $BasePath      = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"

        $UEFICA2023Status = Get-RegValueSafe $ServicingPath "UEFICA2023Status"
        $Capable          = Get-RegValueSafe $ServicingPath "WindowsUEFICA2023Capable"
        $ErrorCode        = Get-RegValueSafe $ServicingPath "UEFICA2023Error"
        $ErrorEvent       = Get-RegValueSafe $ServicingPath "UEFICA2023ErrorEvent"
        $AvailableUpdates = Get-RegValueSafe $BasePath "AvailableUpdates"

        $DBText  = Get-SecureBootVariableText "db"
        $KEKText = Get-SecureBootVariableText "kek"

        $CertInDB  = $DBText -match 'Windows UEFI CA 2023|Microsoft UEFI CA 2023'
        $CertInKEK = $KEKText -match 'Microsoft Corporation KEK 2K CA 2023'

        $TaskInfo = Get-ScheduledTaskStateSafe
        $AvailableUpdatesHex = Convert-ToHexString $AvailableUpdates

        $HasRealErrorCode = Test-RealNonZeroValue $ErrorCode
        $HasRealErrorEvent = Test-RealNonZeroValue $ErrorEvent
        $HasBlockingError = (($UEFICA2023Status -ne "Updated") -and ($HasRealErrorCode -or $HasRealErrorEvent))

        # ====================== MAIN LOGIC ======================
        if (($SecureBootEval.EvalState -eq "Enabled") -and ($UEFICA2023Status -eq "Updated")) {
            $Advisories = @()

            if (-not $TaskInfo.Exists) {
                $Advisories += "Secure-Boot-Update task missing"
            }
            if (-not $CertInDB) {
                $Advisories += "2023 DB cert not confirmed by variable text"
            }
            if (-not $CertInKEK) {
                $Advisories += "2023 KEK cert not confirmed by variable text"
            }
            if ($HasRealErrorCode -or $HasRealErrorEvent) {
                $Advisories += "stale/non-blocking error values present"
            }

            $State = "Fully Updated"
            $Reason = "Secure Boot enabled and UEFICA2023Status = Updated"

            if ($Advisories.Count -gt 0) {
                $Reason = $Reason + "; Advisory: " + ($Advisories -join "; ")
            }

            $ExitCode = 0
        }
        elseif ($UEFICA2023Status -eq "Updated") {
            $State = "Updated - Secure Boot Not Enabled"
            $Reason = "UEFICA2023Status = Updated, but SecureBootEvalState = $($SecureBootEval.EvalState). Microsoft sample compliance expects Secure Boot enabled plus Updated."
            $ExitCode = 1
        }
        elseif ($HasBlockingError) {
            $State = "Error State"
            $Reason = "Non-zero UEFICA2023Error or UEFICA2023ErrorEvent detected while status is not Updated. Error=$ErrorCode; ErrorEvent=$ErrorEvent"
            $ExitCode = 1
        }
        elseif ($SecureBootEval.EvalState -eq "Disabled") {
            $State = "Secure Boot Disabled"
            $Reason = "Secure Boot evaluated as Disabled. UEFICA2023Status=$UEFICA2023Status; AvailableUpdates=$AvailableUpdatesHex"
            $ExitCode = 1
        }
        elseif ($SecureBootEval.EvalState -eq "UnableToEvaluate") {
            $State = "Unable To Evaluate Secure Boot"
            $Reason = "Confirm-SecureBootUEFI failed. Error=$($SecureBootEval.EvalError)"
            $ExitCode = 1
        }
        elseif ($CertInDB -and $CertInKEK) {
            $State = "Certs Present - Awaiting Update"
            $Reason = "2023 certificates detected, but UEFICA2023Status is not Updated"
            $ExitCode = 1
        }
        elseif (($UEFICA2023Status -eq "InProgress") -or ($AvailableUpdatesHex -and $AvailableUpdatesHex -ne "0x0000")) {
            $State = "In Progress"
            $Reason = "Update appears to be in progress. UEFICA2023Status=$UEFICA2023Status; AvailableUpdates=$AvailableUpdatesHex"
            $ExitCode = 1
        }
        elseif ([string]::IsNullOrWhiteSpace($UEFICA2023Status)) {
            $State = "Not Started"
            $Reason = "No UEFICA2023Status value found"
            $ExitCode = 1
        }
        elseif ($UEFICA2023Status -eq "NotStarted") {
            $State = "Not Started"
            $Reason = "UEFICA2023Status = NotStarted. WindowsUEFICA2023Capable=$Capable is reference-only telemetry and is not used as a compliant/not-applicable gate."
            $ExitCode = 1
        }
        else {
            $State = "Needs Review"
            $Reason = "Partial or unknown state. UEFICA2023Status=$UEFICA2023Status; WindowsUEFICA2023Capable=$Capable; SecureBootEvalState=$($SecureBootEval.EvalState)"
            $ExitCode = 1
        }
    }

    # ====================== OUTPUT ======================
    if ($Reason.Length -gt $MaxReasonLength) {
        $Reason = $Reason.Substring(0, $MaxReasonLength) + "..."
    }

    $Result = [ordered]@{
        ScriptVersion                 = $ScriptVersion
        DeviceName                    = $env:COMPUTERNAME
        DetectionTime                 = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        State                         = $State
        ExitCode                      = $ExitCode
        Reason                        = $Reason
        SecureBootEnabled             = $SecureBootEval.Enabled
        SecureBootEvalState           = $SecureBootEval.EvalState
        SecureBootEvalError           = $SecureBootEval.EvalError
        UEFICA2023Status              = $UEFICA2023Status
        WindowsUEFICA2023Capable      = $Capable
        UEFICA2023Error               = $ErrorCode
        UEFICA2023ErrorEvent          = $ErrorEvent
        CertInActiveDB                = $CertInDB
        CertInKEK                     = $CertInKEK
        SecureBootUpdateTaskExists    = $TaskInfo.Exists
        SecureBootUpdateTaskState     = $TaskInfo.State
        AvailableUpdates              = $AvailableUpdatesHex
        FirmwareType                  = $FirmwareType
        LatestTpmWmiEventId           = $EventSummary.LatestTpmWmiEventId
        LatestTpmWmiEventTime         = $EventSummary.LatestTpmWmiEventTime
        Event1808Seen                 = $EventSummary.Event1808Seen
        Latest1808Time                = $EventSummary.Latest1808Time
        Event1808Count                = $EventSummary.Event1808Count
    }

    if ($OutputFormat -eq "Pipe") {
        $PortalOutput = Convert-ToPortalText -Result $Result

        if ($PortalOutput.Length -gt $MaxPortalOutputLength) {
            $ShortReason = if ($Result.Reason.Length -gt 160) { $Result.Reason.Substring(0,160) + "..." } else { $Result.Reason }
            $PortalOutput = "V=$($Result.ScriptVersion) | Device=$($Result.DeviceName) | Exit=$($Result.ExitCode) | State=$($Result.State) | Reason=$ShortReason | SB=$($Result.SecureBootEvalState) | Status=$($Result.UEFICA2023Status) | Cap=$($Result.WindowsUEFICA2023Capable) | Err=$($Result.UEFICA2023Error) | ErrEvt=$($Result.UEFICA2023ErrorEvent) | DB2023=$($Result.CertInActiveDB) | KEK23=$($Result.CertInKEK) | AU=$($Result.AvailableUpdates) | Evt=$($Result.LatestTpmWmiEventId) | E1808=$($Result.Event1808Seen)"
        }
    }
    else {
        $PortalOutput = $Result | ConvertTo-Json -Compress -Depth 4

        if ($PortalOutput.Length -gt $MaxPortalOutputLength) {
            $Compact = [ordered]@{
                V      = $Result.ScriptVersion
                Device = $Result.DeviceName
                State  = $Result.State
                Exit   = $Result.ExitCode
                Reason = if ($Result.Reason.Length -gt 260) { $Result.Reason.Substring(0,260) + "..." } else { $Result.Reason }
                SB     = $Result.SecureBootEvalState
                Status = $Result.UEFICA2023Status
                Err    = $Result.UEFICA2023Error
                ErrEvt = $Result.UEFICA2023ErrorEvent
                Cap    = $Result.WindowsUEFICA2023Capable
                DB2023 = $Result.CertInActiveDB
                KEK23  = $Result.CertInKEK
                AU     = $Result.AvailableUpdates
                Evt    = $Result.LatestTpmWmiEventId
                E1808  = $Result.Event1808Seen
                Log    = $LogPath
            }
            $PortalOutput = $Compact | ConvertTo-Json -Compress
        }
    }

    Write-Output $PortalOutput
    Write-Log "Completed - State: $State | Exit: $ExitCode | Status: $UEFICA2023Status | SB: $($SecureBootEval.EvalState)"

    exit $ExitCode
}
catch {
    $ErrorReason = if ($_.Exception.Message.Length -gt $MaxReasonLength) {
        $_.Exception.Message.Substring(0, $MaxReasonLength) + "..."
    }
    else {
        $_.Exception.Message
    }

    Write-Log "ERROR: $ErrorReason"

    $ErrorResult = [ordered]@{
        ScriptVersion = $ScriptVersion
        DeviceName    = $env:COMPUTERNAME
        State         = "Script Error"
        Reason        = $ErrorReason
        ExitCode      = 1
    } | ConvertTo-Json -Compress

    Write-Output $ErrorResult
    exit 1
}
