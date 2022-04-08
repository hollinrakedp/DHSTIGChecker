<#
Rule Title: Windows Server 2019 Modify firmware environment values user right must only be assigned to the Administrators group.
Severity: medium
Vuln ID: V-205764
STIG ID: WN19-UR-000180

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
return 'Not Reviewed'
