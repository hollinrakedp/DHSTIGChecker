<#
Rule Title: The Windows PowerShell 2.0 feature must be disabled on the system.
Severity: medium
Vuln ID: V-220728
STIG ID: WN10-00-000155

Discussion:
Windows PowerShell 5.0 added advanced logging features which can provide additional detail when malware has been run on a system.  Disabling the Windows PowerShell 2.0 mitigates against a downgrade attack that evades the Windows PowerShell 5.0 script block logging feature.


Check Content:
Run "Windows PowerShell" with elevated privileges (run as administrator).

Enter the following:
Get-WindowsOptionalFeature -Online | Where FeatureName -like *PowerShellv2*

If either of the following have a "State" of "Enabled", this is a finding.

FeatureName : MicrosoftWindowsPowerShellV2
State : Enabled
FeatureName : MicrosoftWindowsPowerShellV2Root
State : Enabled

Alternately:
Search for "Features".

Select "Turn Windows features on or off".

If "Windows PowerShell 2.0" (whether the subcategory of "Windows PowerShell 2.0 Engine" is selected or not) is selected, this is a finding.

#>

$PowerShellv2 = Get-WindowsOptionalFeature -Online -Verbose:$false | Where-Object {$_.FeatureName -like "*PowerShellv2*"}

if ($PowerShellv2.State -contains 'Enabled') {
    $false
}
else {
    $true
}