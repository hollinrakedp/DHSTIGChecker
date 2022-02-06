<#
Rule Title: The Access this computer from the network user right must only be assigned to the Administrators and Remote Desktop Users groups.
Severity: medium
Vuln ID: V-220957
STIG ID: WN10-UR-000010

Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Access this computer from the network" user right may access resources on the system, and must be limited to those that require it.


Check Content:
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Access this computer from the network" user right, this is a finding:

Administrators
Remote Desktop Users

If a domain application account such as for a management tool requires this user right, this would not be a finding.

Vendor documentation must support the requirement for having the user right.

The requirement must be documented with the ISSO.

The application account, managed at the domain level, must meet requirements for application account passwords, such as length and frequency of changes as defined in the Windows server STIGs.

#>

$GrantedPrivilege = ($Script:CurrentSecPolicy.SeNetworkLogonRight -split ',').trimstart('*')

$Allowed = @($Script:SIDLocalGroup.Administrators,
    $Script:SIDLocalGroup.RemoteDesktopUsers)

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