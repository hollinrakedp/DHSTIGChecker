<#
Rule Title: Windows Server 2019 Access this computer from the network user right must only be assigned to the Administrators, Authenticated Users, and 
Enterprise Domain Controllers groups on domain controllers.
Severity: medium
Vuln ID: V-205665
STIG ID: WN19-DC-000340

Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Access this computer from the network" right may access resources on the system, and this right must be limited to those requiring it.


Check Content:
This applies to domain controllers. It is NA for other systems.

Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Access this computer from the network" right, this is a finding.

- Administrators
- Authenticated Users
- Enterprise Domain Controllers

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\path\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeNetworkLogonRight" user right, this is a finding.

S-1-5-32-544 (Administrators)
S-1-5-11 (Authenticated Users)
S-1-5-9 (Enterprise Domain Controllers)

If an application requires this user right, this would not be a finding.

Vendor documentation must support the requirement for having the user right.

The requirement must be documented with the ISSO.

The application account must meet requirements for application account passwords, such as length (WN19-00-000050) and required frequency of changes (WN19-00-000060).

#>

if ($Script:IsDomainController) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}