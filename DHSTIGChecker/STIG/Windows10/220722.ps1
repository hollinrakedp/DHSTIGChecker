<#
Rule Title: The TFTP Client must not be installed on the system.
Severity: medium
Vuln ID: V-220722
STIG ID: WN10-00-000120

Discussion:
Some protocols and services do not support required security features, such as encrypting passwords or traffic.


Check Content:
The "TFTP Client" is not installed by default.  Verify it has not been installed.

Navigate to the Windows\System32 directory.

If the "TFTP" application exists, this is a finding.

#>

$Local:Feature = Get-WindowsOptionalFeature -Online -FeatureName "TFTP"

if ($Local:Feature.State -contains 'Enabled') {
    $false
}
else {
    $true
}