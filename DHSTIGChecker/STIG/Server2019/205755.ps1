<#
Rule Title: Windows Server 2019 Create permanent shared objects user right must not be assigned to any groups or accounts.
Severity: medium
Vuln ID: V-205755
STIG ID: WN19-UR-000080

Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Create permanent shared objects" user right could expose sensitive data by creating shared objects.


Check Content:
Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups are granted the "Create permanent shared objects" user right, this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\path\filename.txt

Review the text file.

If any SIDs are granted the "SeCreatePermanentPrivilege" user right, this is a finding.

#>
return 'Not Reviewed'
