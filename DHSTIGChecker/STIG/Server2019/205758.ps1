<#
Rule Title: Windows Server 2019 Force shutdown from a remote system user right must only be assigned to the Administrators group.
Severity: medium
Vuln ID: V-205758
STIG ID: WN19-UR-000110

Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Force shutdown from a remote system" user right can remotely shut down a system, which could result in a denial of service.


Check Content:
Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Force shutdown from a remote system" user right, this is a finding:

- Administrators

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\path\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeRemoteShutdownPrivilege" user right, this is a finding:

S-1-5-32-544 (Administrators)

#>
return 'Not Reviewed'
