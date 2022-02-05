<#
Rule Title: Simple TCP/IP Services must not be installed on the system.
Severity: medium
Vuln ID: V-220720
STIG ID: WN10-00-000110

Discussion:
Some protocols and services do not support required security features, such as encrypting passwords or traffic.


Check Content:
"Simple TCP/IP Services" is not installed by default.  Verify it has not been installed.

Run "Services.msc".

If "Simple TCP/IP Services" is listed, this is a finding.

#>
$Local:Service = @()
$Local:Service += Get-Service -Name "simptcp" -ErrorAction SilentlyContinue

if ($Local:Service.Count -ne 0) {
    $false
}
else {
    $true
}