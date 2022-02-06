<#
Rule Title: The Create a token object user right must not be assigned to any groups or accounts.
Severity: high
Vuln ID: V-220963
STIG ID: WN10-UR-000045

Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Create a token object" user right allows a process to create an access token. This could be used to provide elevated rights and compromise a system.


Check Content:
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts are granted the "Create a token object" user right, this is a finding.

#>

$GrantedPrivilege = ($Script:CurrentSecPolicy.SeCreateTokenPrivilege -split ',').trimstart('*')

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