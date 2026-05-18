# =========================
# MDE Readiness Detection
# One-line output for Intune
# v3 - fixes: AVEnabled/RTP severity, IsTamperProtected guard,
#              OnboardingState=0, HealthState=3
# =========================

$script:nonCompliant = $false
$script:parts = @()

function Add-Part {
    param(
        [string]$Severity,
        [string]$Name,
        [string]$Value
    )

    $script:parts += "[{0}]{1}={2}" -f $Severity, $Name, $Value

    if ($Severity -eq "ERR") {
        $script:nonCompliant = $true
    }
}

function Convert-FileTime {
    param(
        [Parameter(Mandatory = $false)]
        $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -eq 0) {
        return $null
    }

    try {
        $ft = [Int64]$Value
        if ($ft -le 0) {
            return $null
        }

        return [DateTime]::FromFileTimeUtc($ft).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
    }
    catch {
        return $null
    }
}

# -------------------------
# Read MDE registry status
# -------------------------
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status"
$atp = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue

if ($null -ne $atp) {
    Add-Part -Severity "OK" -Name "StatusKey" -Value "Present"
}
else {
    Add-Part -Severity "ERR" -Name "StatusKey" -Value "Missing"
}

# -------------------------
# Sense service
# -------------------------
$sense = Get-Service -Name "Sense" -ErrorAction SilentlyContinue

if ($null -eq $sense) {
    Add-Part -Severity "ERR" -Name "SenseService" -Value "Missing"
}
elseif ($sense.Status -eq "Running") {
    Add-Part -Severity "OK" -Name "SenseService" -Value "Running"
}
else {
    Add-Part -Severity "ERR" -Name "SenseService" -Value ([string]$sense.Status)
    Add-Part -Severity "WARN" -Name "HintSense" -Value "ServiceNotRunning"
}

# -------------------------
# Onboarding state
# FIX: explicit handling of state 0 (offboarded)
# -------------------------
$onboardingState = $null
if ($null -ne $atp) {
    $onboardingState = $atp.OnboardingState
}

if ($onboardingState -eq 1) {
    Add-Part -Severity "OK" -Name "Onboarding" -Value "OK"
}
elseif ($onboardingState -eq 0) {
    Add-Part -Severity "ERR" -Name "Onboarding" -Value "Offboarded"
    Add-Part -Severity "WARN" -Name "HintOnboarding" -Value "DeviceOffboarded"
}
elseif ($null -eq $onboardingState -or [string]::IsNullOrWhiteSpace([string]$onboardingState)) {
    Add-Part -Severity "ERR" -Name "Onboarding" -Value "Unknown"
    Add-Part -Severity "WARN" -Name "HintOnboarding" -Value "StateMissing"
}
else {
    Add-Part -Severity "ERR" -Name "Onboarding" -Value ([string]$onboardingState)
    Add-Part -Severity "WARN" -Name "HintOnboarding" -Value "PolicyOrRegistrationIssue"
}

# -------------------------
# OrgId
# -------------------------
if ($null -ne $atp -and -not [string]::IsNullOrWhiteSpace([string]$atp.OrgId)) {
    Add-Part -Severity "OK" -Name "OrgId" -Value "Present"
}
else {
    Add-Part -Severity "ERR" -Name "OrgId" -Value "Missing"
    Add-Part -Severity "WARN" -Name "HintOrgId" -Value "OnboardingIncompleteOrRegistrationIssue"
}

# -------------------------
# Health state
# FIX: added explicit HealthState=3 (ImpairedCommunications)
# -------------------------
$healthState = $null
if ($null -ne $atp) {
    $healthState = $atp.HealthState
}

if ($null -eq $healthState -or [string]::IsNullOrWhiteSpace([string]$healthState)) {
    Add-Part -Severity "WARN" -Name "Health" -Value "Unknown"
    Add-Part -Severity "WARN" -Name "HintHealth" -Value "OnboardedButNoSensorHealthOrTelemetryDelay"
}
else {
    switch ([int]$healthState) {
        0 {
            Add-Part -Severity "OK" -Name "Health" -Value "Healthy"
        }
        1 {
            Add-Part -Severity "ERR" -Name "Health" -Value "NoData"
            Add-Part -Severity "WARN" -Name "HintHealth" -Value "CheckTelemetryConnectivityProxy"
        }
        2 {
            Add-Part -Severity "ERR" -Name "Health" -Value "Pending"
            Add-Part -Severity "WARN" -Name "HintHealth" -Value "OnboardingNotFullyInitialized"
        }
        3 {
            Add-Part -Severity "ERR" -Name "Health" -Value "ImpairedCommunications"
            Add-Part -Severity "WARN" -Name "HintHealth" -Value "CheckNetworkProxyOrTLSInspection"
        }
        default {
            Add-Part -Severity "WARN" -Name "Health" -Value ([string]$healthState)
            Add-Part -Severity "WARN" -Name "HintHealth" -Value "UnexpectedHealthState"
        }
    }
}

# -------------------------
# Last connected / Last seen
# -------------------------
$lastConnectedRaw = $null
if ($null -ne $atp) {
    $lastConnectedRaw = $atp.LastConnected
}

$lastSeenText = Convert-FileTime -Value $lastConnectedRaw

if (-not [string]::IsNullOrWhiteSpace($lastSeenText)) {
    Add-Part -Severity "OK" -Name "LastSeen" -Value $lastSeenText

    try {
        $lastSeenDate = [datetime]::ParseExact($lastSeenText, "yyyy-MM-dd HH:mm:ss", $null)
        $ageHours = [math]::Round(((Get-Date) - $lastSeenDate).TotalHours, 1)

        if ($ageHours -gt 24) {
            Add-Part -Severity "WARN" -Name "LastSeenAgeHours" -Value ([string]$ageHours)
            Add-Part -Severity "WARN" -Name "HintLastSeen" -Value "OlderThan24Hours"
        }
        else {
            Add-Part -Severity "OK" -Name "LastSeenAgeHours" -Value ([string]$ageHours)
        }
    }
    catch {
        Add-Part -Severity "WARN" -Name "LastSeenAgeHours" -Value "Unknown"
    }
}
else {
    Add-Part -Severity "WARN" -Name "LastSeen" -Value "Unknown"
    Add-Part -Severity "WARN" -Name "HintLastSeen" -Value "NoSuccessfulConnectionRecorded"
}

# -------------------------
# Defender AV status
# FIX: AVEnabled/RTP severity derived from actual value, not hardcoded OK
# FIX: IsTamperProtected wrapped in property guard
# -------------------------
$mp = Get-MpComputerStatus -ErrorAction SilentlyContinue

if ($null -ne $mp) {

    # AVEnabled
    if ($mp.AntivirusEnabled -eq $true) {
        Add-Part -Severity "OK"   -Name "AVEnabled" -Value "True"
    }
    else {
        Add-Part -Severity "WARN" -Name "AVEnabled" -Value "False"
        Add-Part -Severity "WARN" -Name "HintAV" -Value "DefenderAVNotPrimary"
    }

    # RTP
    if ($mp.RealTimeProtectionEnabled -eq $true) {
        Add-Part -Severity "OK"   -Name "RTP" -Value "True"
    }
    else {
        Add-Part -Severity "WARN" -Name "RTP" -Value "False"
        Add-Part -Severity "WARN" -Name "HintRTP" -Value "RealTimeProtectionDisabled"
    }

    # AMRunningMode
    if ($mp.PSObject.Properties.Name -contains "AMRunningMode") {
        Add-Part -Severity "OK" -Name "AMRunningMode" -Value ([string]$mp.AMRunningMode)

        if ([string]$mp.AMRunningMode -match "Passive") {
            Add-Part -Severity "WARN" -Name "HintMode" -Value "PassiveMode"
        }
    }

    # IsTamperProtected - property guard, consistent with AMRunningMode pattern
    if ($mp.PSObject.Properties.Name -contains "IsTamperProtected") {
        if ($mp.IsTamperProtected -eq $true) {
            Add-Part -Severity "OK"   -Name "Tamper" -Value "Enabled"
        }
        elseif ($mp.IsTamperProtected -eq $false) {
            Add-Part -Severity "WARN" -Name "Tamper" -Value "Disabled"
            Add-Part -Severity "WARN" -Name "HintTamper" -Value "TamperProtectionDisabled"
        }
        else {
            Add-Part -Severity "WARN" -Name "Tamper" -Value "Unknown"
        }
    }
    else {
        Add-Part -Severity "WARN" -Name "Tamper" -Value "PropertyMissing"
    }
}
else {
    Add-Part -Severity "WARN" -Name "DefenderStatus" -Value "Unavailable"
    Add-Part -Severity "WARN" -Name "HintDefender" -Value "GetMpComputerStatusUnavailable"
}

# -------------------------
# Final one-line output
# -------------------------
$result = "COMPLIANT"
if ($script:nonCompliant) {
    $result = "NONCOMPLIANT"
}

$output = "RESULT={0}" -f $result

if ($script:parts.Count -gt 0) {
    $output = $output + " | " + ($script:parts -join " | ")
}

Write-Output $output

if ($script:nonCompliant) {
    exit 1
}
else {
    exit 0
}
