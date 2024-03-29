# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253487
Rule ID:    SV-253487r877392_rule
STIG ID:    WN11-UR-000050
Legacy:     
Rule Title: The "Create global objects" user right must only be assigned to Administrators, Service, Local Service, and Network Service.
Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Create global objects" user right can create objects that are available to all sessions, which could affect processes in other users' sessions.


Check Content:
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Create global objects" user right, this is a finding:

Administrators
LOCAL SERVICE
NETWORK SERVICE
SERVICE
#>

$GrantedPrivilege = ($Script:CurrentSecPolicy.SeCreateGlobalPrivilege -split ',').trimstart('*')

$Allowed = @($Script:SIDLocalGroup.Administrators,
$Script:SIDLocalGroup.LocalService,
$Script:SIDLocalGroup.NetworkService
$Script:SIDLocalGroup.Service)

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