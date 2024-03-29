# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205760
Rule ID:    SV-205760r877392_rule
STIG ID:    WN19-UR-000130
Legacy:     V-93071; SV-103159
Rule Title: Windows Server 2019 Impersonate a client after authentication user right must only be assigned to Administrators, Service, Local Service, and Network Service.
Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Impersonate a client after authentication" user right allows a program to impersonate another user or account to run on their behalf. An attacker could use this to elevate privileges.


Check Content:
Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Impersonate a client after authentication" user right, this is a finding:

- Administrators
- Service
- Local Service
- Network Service

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\path\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeImpersonatePrivilege" user right, this is a finding:

S-1-5-32-544 (Administrators)
S-1-5-6 (Service)
S-1-5-19 (Local Service)
S-1-5-20 (Network Service)

If an application requires this user right, this would not be a finding.

Vendor documentation must support the requirement for having the user right.

The requirement must be documented with the ISSO.

The application account must meet requirements for application account passwords, such as length (WN19-00-000050) and required frequency of changes (WN19-00-000060).
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