<#
Rule Title: Windows Server 2019 Add workstations to domain user right must only be assigned to the Administrators group on domain controllers.
Severity: medium
Vuln ID: V-205744
STIG ID: WN19-DC-000350

Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Add workstations to domain" right may add computers to a domain. This could result in unapproved or incorrectly configured systems being added to a domain.


Check Content:
This applies to domain controllers. It is NA for other systems.

Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Add workstations to domain" right, this is a finding.

- Administrators

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\path\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeMachineAccountPrivilege" user right, this is a finding.

S-1-5-32-544 (Administrators)

#>

if ($Script:IsDomainController) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}