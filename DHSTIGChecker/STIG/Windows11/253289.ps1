# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253289
Rule ID:    SV-253289r828951_rule
STIG ID:    WN11-00-000175
Legacy:     
Rule Title: The Secondary Logon service must be disabled on Windows 11.
Discussion:
The Secondary Logon service provides a means for entering alternate credentials, typically used to run commands with elevated privileges. Using privileged credentials in a standard user session can expose those credentials to theft.


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