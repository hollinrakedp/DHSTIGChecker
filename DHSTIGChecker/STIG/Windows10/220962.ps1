<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 5 Benchmark Date: 14 Nov 2022
Severity:   medium
Vuln ID:    V-220962
Rule ID:    SV-220962r852023_rule
STIG ID:    WN10-UR-000040
Legacy:     V-63857; SV-78347
Rule Title: The Create a pagefile user right must only be assigned to the Administrators group.
Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Create a pagefile" user right can change the size of a pagefile, which could affect system performance.


Check Content:
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Create a pagefile" user right, this is a finding:

Administrators
#>

$GrantedPrivilege = ($Script:CurrentSecPolicy.SeCreatePagefilePrivilege -split ',').trimstart('*')

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