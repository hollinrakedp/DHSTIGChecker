# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253444
Rule ID:    SV-253444r840185_rule
STIG ID:    WN11-SO-000070
Legacy:     
Rule Title: The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver.
Discussion:
Unattended systems are susceptible to unauthorized use and must be locked when unattended. The screen saver must be set at a maximum of 15 minutes and be password protected. This protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer.

Satisfies: SRG-OS-000279-GPOS-00109, SRG-OS-000163-GPOS-00072


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: InactivityTimeoutSecs

Value Type: REG_DWORD
Value: 0x00000384 (900) (or less, excluding "0" which is effectively disabled)
#>

$Local:Results = @()

$Params = @{
    Path          = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
    Name          = "InactivityTimeoutSecs"
    ExpectedValue = 900
    Comparison    = "le"
}

$Local:Results += Compare-RegKeyValue @Params

$Params = @{
    Path          = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
    Name          = "InactivityTimeoutSecs"
    ExpectedValue = 0
    Comparison    = "ne"
}

$Local:Results += Compare-RegKeyValue @Params

if ($Local:Results -contains $false) {
    $false
}
else {
    $true
}