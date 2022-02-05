<#
Rule Title: The Impersonate a client after authentication user right must only be assigned to Administrators, Service, Local Service, and Network Service.
Severity: medium
Vuln ID: V-220975
STIG ID: WN10-UR-000110

Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Impersonate a client after authentication" user right allows a program to impersonate another user or account to run on their behalf. An attacker could potentially use this to elevate privileges.


Check Content:
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Impersonate a client after authentication" user right, this is a finding:

Administrators
LOCAL SERVICE
NETWORK SERVICE
SERVICE

#>

$GrantedPrivilege = ($Script:CurrentSecPolicy.SeImpersonatePrivilege -split ',').trimstart('*')

$Allowed = @($Script:SIDLocalGroup.Administrators,
    $Script:SIDLocalGroup.LocalService,
    $Script:SIDLocalGroup.NetworkService,
    $Script:SIDLocalGroup.Service
)

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