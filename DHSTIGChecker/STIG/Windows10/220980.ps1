# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220980
Rule ID:    SV-220980r877392_rule
STIG ID:    WN10-UR-000145
Legacy:     V-63933; SV-78423
Rule Title: The Perform volume maintenance tasks user right must only be assigned to the Administrators group.
Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Perform volume maintenance tasks" user right can manage volume and disk configurations. They could potentially delete volumes, resulting in, data loss or a DoS.


Check Content:
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Perform volume maintenance tasks" user right, this is a finding:

Administrators
#>

$GrantedPrivilege = ($Script:CurrentSecPolicy.SeManageVolumePrivilege -split ',').trimstart('*')

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