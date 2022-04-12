<#
Rule Title: Windows Server 2016 minimum password age must be configured to at least one day.
Severity: medium
Vuln ID: V-224871
STIG ID: WN16-AC-000060

Discussion:
Permitting passwords to be changed in immediate succession within the same day allows users to cycle passwords through their history database. This enables users to effectively negate the purpose of mandating periodic password changes.


Check Content:
Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.

If the value for the "Minimum password age" is set to "0" days ("Password can be changed immediately"), this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas SecurityPolicy /CFG C:\Path\FileName.Txt

If "MinimumPasswordAge" equals "0" in the file, this is a finding.

#>

$Local:Result = Get-CurrentSecurityPolicySetting -Policy "MinimumPasswordAge"

if ($Local:Result -gt 0) {
    $true
}
else {
    $false
}