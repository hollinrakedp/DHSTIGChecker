# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205764
Rule ID:    SV-205764r877392_rule
STIG ID:    WN19-UR-000180
Legacy:     V-93079; SV-103167
Rule Title: Windows Server 2019 Modify firmware environment values user right must only be assigned to the Administrators group.
Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Modify firmware environment values" user right can change hardware configuration environment variables. This could result in hardware failures or a denial of service.


Check Content:
Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Modify firmware environment values" user right, this is a finding:

- Administrators

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\path\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeSystemEnvironmentPrivilege" user right, this is a finding:

S-1-5-32-544 (Administrators)
#>

$GrantedPrivilege = ($Script:CurrentSecPolicy.SeSystemEnvironmentPrivilege -split ',').trimstart('*')

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