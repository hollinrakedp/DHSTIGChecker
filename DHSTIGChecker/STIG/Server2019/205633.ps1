# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205633
Rule ID:    SV-205633r569188_rule
STIG ID:    WN19-SO-000120
Legacy:     V-92961; SV-103049
Rule Title: Windows Server 2019 machine inactivity limit must be set to 15 minutes or less, locking the system with the screen saver.
Discussion:
Unattended systems are susceptible to unauthorized use and should be locked when unattended. The screen saver should be set at a maximum of 15 minutes and be password protected. This protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer.

Satisfies: SRG-OS-000028-GPOS-00009, SRG-OS-000029-GPOS-00010, SRG-OS-000031-GPOS-00012


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