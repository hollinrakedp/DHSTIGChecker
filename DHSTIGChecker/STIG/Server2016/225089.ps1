<#
Rule Title: The Profile single process user right must only be assigned to the Administrators group.
Severity: medium
Vuln ID: V-225089
STIG ID: WN16-UR-000290

Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Profile single process" user right can monitor non-system processes performance. An attacker could use this to identify processes to attack.


Check Content:
Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Profile single process" user right, this is a finding.

- Administrators

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\path\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeProfileSingleProcessPrivilege" user right, this is a finding.

S-1-5-32-544 (Administrators)

#>
return 'Not Reviewed'
