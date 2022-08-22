<#
Rule Title: Windows Server 2019 Deny log on as a service user right must be configured to include no accounts or groups (blank) on domain controllers.
Severity: medium
Vuln ID: V-205669
STIG ID: WN19-DC-000390

Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Deny log on as a service" user right defines accounts that are denied logon as a service.

Incorrect configurations could prevent services from starting and result in a denial of service.


Check Content:
This applies to domain controllers. A separate version applies to other systems.

Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups are defined for the "Deny log on as a service" user right, this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\path\filename.txt

Review the text file.

If any SIDs are granted the "SeDenyServiceLogonRight" user right, this is a finding.

#>

if ($Script:IsDomainController) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}