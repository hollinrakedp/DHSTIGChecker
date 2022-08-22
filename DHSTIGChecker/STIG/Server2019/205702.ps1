<#
Rule Title: Windows Server 2019 Kerberos user logon restrictions must be enforced.
Severity: medium
Vuln ID: V-205702
STIG ID: WN19-DC-000020

Discussion:
This policy setting determines whether the Kerberos Key Distribution Center (KDC) validates every request for a session ticket against the user rights policy of the target computer. The policy is enabled by default, which is the most secure setting for validating that access to target resources is not circumvented.

Satisfies: SRG-OS-000112-GPOS-00057, SRG-OS-000113-GPOS-00058


Check Content:
This applies to domain controllers. It is NA for other systems.

Verify the following is configured in the Default Domain Policy:

Open "Group Policy Management".

Navigate to "Group Policy Objects" in the Domain being reviewed (Forest >> Domains >> Domain). 

Right-click on the "Default Domain Policy".

Select "Edit".

Navigate to Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy.

If the "Enforce user logon restrictions" is not set to "Enabled", this is a finding.

#>

if ($Script:IsDomainController) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}