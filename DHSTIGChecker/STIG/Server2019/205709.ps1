<#
Rule Title: Windows Server 2019 must have the built-in guest account disabled.
Severity: medium
Vuln ID: V-205709
STIG ID: WN19-SO-000010

Discussion:
A system faces an increased vulnerability threat if the built-in guest account is not disabled. This is a known account that exists on all Windows systems and cannot be deleted. This account is initialized during the installation of the operating system with no password assigned.


Check Content:
Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options.

If the value for "Accounts: Guest account status" is not set to "Disabled", this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas SecurityPolicy /CFG C:\Path\FileName.Txt

If "EnableGuestAccount" equals "1" in the file, this is a finding.

#>
return 'Not Reviewed'
