# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220732
Rule ID:    SV-220732r569187_rule
STIG ID:    WN10-00-000175
Legacy:     V-74719; SV-89393
Rule Title: The Secondary Logon service must be disabled on Windows 10.
Discussion:
The Secondary Logon service provides a means for entering alternate credentials, typically used to run commands with elevated privileges.  Using privileged credentials in a standard user session can expose those credentials to theft.


Check Content:
Run "Services.msc".

Locate the "Secondary Logon" service.

If the "Startup Type" is not "Disabled" or the "Status" is "Running", this is a finding.
#>

$Local:Service = Get-Service -Name seclogon
if (($Local:Service.StartType -ne 'Disabled') -or ($Local:Service.Status -eq 'Running')) {
    $false
}
else {
    $true
}