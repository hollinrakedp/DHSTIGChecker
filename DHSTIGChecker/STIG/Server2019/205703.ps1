<#
Rule Title: Windows Server 2019 Kerberos service ticket maximum lifetime must be limited to 600 minutes or less.
Severity: medium
Vuln ID: V-205703
STIG ID: WN19-DC-000030

Discussion:
This setting determines the maximum amount of time (in minutes) that a granted session ticket can be used to access a particular service. Session tickets are used only to authenticate new connections with servers. Ongoing operations are not interrupted if the session ticket used to authenticate the connection expires during the connection.

Satisfies: SRG-OS-000112-GPOS-00057, SRG-OS-000113-GPOS-00058


Check Content:
This applies to domain controllers. It is NA for other systems.

Verify the following is configured in the Default Domain Policy:

Open "Group Policy Management".

Navigate to "Group Policy Objects" in the Domain being reviewed (Forest >> Domains >> Domain). 

Right-click on the "Default Domain Policy".

Select "Edit".

Navigate to Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy.

If the value for "Maximum lifetime for service ticket" is "0" or greater than "600" minutes, this is a finding.

#>

if ($Script:IsDomainController) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}