<#
Rule Title: Windows Server 2019 minimum password length must be configured to 14 characters.
Severity: medium
Vuln ID: V-205662
STIG ID: WN19-AC-000070

Discussion:
Information systems not protected with strong password schemes (including passwords of minimum length) provide the opportunity for anyone to crack the password, thus gaining access to the system and compromising the device, information, or the local network.


Check Content:
Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.

If the value for the "Minimum password length," is less than "14" characters, this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas SecurityPolicy /CFG C:\Path\FileName.Txt

If "MinimumPasswordLength" is less than "14" in the file, this is a finding.

#>

$Local:Result = Get-CurrentSecurityPolicySetting -Policy "MinimumPasswordLength"

if ($Local:Result -ge 14) {
    $true
}
else {
    $false
}