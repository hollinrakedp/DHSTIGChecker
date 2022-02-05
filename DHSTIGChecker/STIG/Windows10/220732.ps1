<#
Rule Title: The Secondary Logon service must be disabled on Windows 10.
Severity: medium
Vuln ID: V-220732
STIG ID: WN10-00-000175

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