<#
Rule Title: Windows Server 2016 built-in administrator account must be renamed.
Severity: medium
Vuln ID: V-225026
STIG ID: WN16-SO-000030

Discussion:
The built-in administrator account is a well-known account subject to attack. Renaming this account to an unidentified name improves the protection of this account and the system.


Check Content:
Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options.

If the value for "Accounts: Rename administrator account" is not set to a value other than "Administrator", this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas SecurityPolicy /CFG C:\Path\FileName.Txt

If "NewAdministratorName" is not something other than "Administrator" in the file, this is a finding.

#>
return 'Not Reviewed'
