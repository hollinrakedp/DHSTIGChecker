<#
Rule Title: Windows Server 2019 Deny access to this computer from the network user right on domain controllers must be configured to prevent unauthenticated access.
Severity: medium
Vuln ID: V-205667
STIG ID: WN19-DC-000370

Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Deny access to this computer from the network" user right defines the accounts that are prevented from logging on from the network.

The Guests group must be assigned this right to prevent unauthenticated access.


Check Content:
This applies to domain controllers. A separate version applies to other systems.

Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny access to this computer from the network" user right, this is a finding:

- Guests Group

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\path\filename.txt

Review the text file.

If the following SIDs are not defined for the "SeDenyNetworkLogonRight" user right, this is a finding.

S-1-5-32-546 (Guests)

#>

if ($Script:IsDomainController) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}