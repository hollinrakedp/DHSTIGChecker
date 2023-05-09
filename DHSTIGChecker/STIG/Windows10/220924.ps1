<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 5 Benchmark Date: 14 Nov 2022
Severity:   medium
Vuln ID:    V-220924
Rule ID:    SV-220924r569187_rule
STIG ID:    WN10-SO-000095
Legacy:     V-63697; SV-78187
Rule Title: The Smart Card removal option must be configured to Force Logoff or Lock Workstation.
Discussion:
Unattended systems are susceptible to unauthorized use and must be locked.  Configuring a system to lock when a smart card is removed will ensure the system is inaccessible when unattended.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\

Value Name:  SCRemoveOption

Value Type:  REG_SZ
Value:  1 (Lock Workstation) or 2 (Force Logoff)

This can be left not configured or set to "No action" on workstations with the following conditions.  This must be documented with the ISSO.
-The setting cannot be configured due to mission needs, or because it interferes with applications.
-Policy must be in place that users manually lock workstations when leaving them unattended.
-The screen saver is properly configured to lock as required.
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