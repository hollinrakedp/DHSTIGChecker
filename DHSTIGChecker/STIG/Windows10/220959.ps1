# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220959
Rule ID:    SV-220959r569187_rule
STIG ID:    WN10-UR-000025
Legacy:     V-63851; SV-78341
Rule Title: The Allow log on locally user right must only be assigned to the Administrators and Users groups.
Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Allow log on locally" user right can log on interactively to a system.


Check Content:
Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Allow log on locally" user right, this is a finding:

Administrators
Users
#>

$GrantedPrivilege = ($Script:CurrentSecPolicy.SeInteractiveLogonRight -split ',').trimstart('*')

$Allowed = @($Script:SIDLocalGroup.Administrators,
    $Script:SIDLocalGroup.Users)

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