# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-225038
Rule ID:    SV-225038r569186_rule
STIG ID:    WN16-SO-000180
Legacy:     V-73807; SV-88473
Rule Title: The Smart Card removal option must be configured to Force Logoff or Lock Workstation.
Discussion:
Unattended systems are susceptible to unauthorized use and must be locked. Configuring a system to lock when a smart card is removed will ensure the system is inaccessible when unattended.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\
 
Value Name: scremoveoption

Value Type: REG_SZ
Value: 1 (Lock Workstation) or 2 (Force Logoff)

If configuring this on servers causes issues, such as terminating users' remote sessions, and the organization has a policy in place that any other sessions on the servers, such as administrative console logons, are manually locked or logged off when unattended or not in use, this would be acceptable. This must be documented with the ISSO.
#>

$Local:Results = @()
$Local:ValidValues = 1, 2

foreach ($Value in $Local:ValidValues) {
    $Params = @{
        Path          = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\"
        Name          = "SCRemoveOption"
        ExpectedValue = $Value
    }

    $Local:Results += Compare-RegKeyValue @Params
}

if ($Local:Results -contains $true) {
    $true
}
else {
    $false
}