# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220976
Rule ID:    SV-220976r877392_rule
STIG ID:    WN10-UR-000120
Legacy:     V-63917; SV-78407
Rule Title: The Load and unload device drivers user right must only be assigned to the Administrators group.
Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Load and unload device drivers" user right allows device drivers to dynamically be loaded on a system by a user. This could potentially be used to install malicious code by an attacker.


Check Content:
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Load and unload device drivers" user right, this is a finding:

Administrators
#>

$GrantedPrivilege = ($Script:CurrentSecPolicy.SeLoadDriverPrivilege -split ',').trimstart('*')

$Allowed = @($Script:SIDLocalGroup.Administrators)

$Local:Results = @()

foreach ($ID in $GrantedPrivilege) {
    $Local:Results += if ($Allowed -contains $ID ) {
        $true
    }
    else {
        $false
    }
}

if ($Local:Results -contains $false) {
    $false
}
else {
    $true
}