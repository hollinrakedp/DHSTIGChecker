# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205756
Rule ID:    SV-205756r877392_rule
STIG ID:    WN19-UR-000090
Legacy:     V-93063; SV-103151
Rule Title: Windows Server 2019 Create symbolic links user right must only be assigned to the Administrators group.
Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Create symbolic links" user right can create pointers to other objects, which could expose the system to attack.


Check Content:
Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Create symbolic links" user right, this is a finding:

- Administrators

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\path\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeCreateSymbolicLinkPrivilege" user right, this is a finding:

S-1-5-32-544 (Administrators)

Systems that have the Hyper-V role will also have "Virtual Machines" given this user right (this may be displayed as "NT Virtual Machine\Virtual Machines", SID S-1-5-83-0). This is not a finding.
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