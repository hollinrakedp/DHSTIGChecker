# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205912
Rule ID:    SV-205912r569188_rule
STIG ID:    WN19-SO-000150
Legacy:     V-93287; SV-103375
Rule Title: Windows Server 2019 Smart Card removal option must be configured to Force Logoff or Lock Workstation.
Discussion:
Unattended systems are susceptible to unauthorized use and must be locked. Configuring a system to lock when a smart card is removed will ensure the system is inaccessible when unattended.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

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