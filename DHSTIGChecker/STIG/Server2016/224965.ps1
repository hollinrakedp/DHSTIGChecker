# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224965
Rule ID:    SV-224965r852340_rule
STIG ID:    WN16-DC-000020
Legacy:     V-73359; SV-88011
Rule Title: Kerberos user logon restrictions must be enforced.
Discussion:
This policy setting determines whether the Kerberos Key Distribution Center (KDC) validates every request for a session ticket against the user rights policy of the target computer. The policy is enabled by default, which is the most secure setting for validating that access to target resources is not circumvented.

Satisfies: SRG-OS-000112-GPOS-00057, SRG-OS-000113-GPOS-00058


Check Content:
This applies to domain controllers. It is NA for other systems.

Verify the following is configured in the Default Domain Policy.

Open "Group Policy Management".

Navigate to "Group Policy Objects" in the Domain being reviewed (Forest >> Domains >> Domain). 

Right-click on the "Default Domain Policy".

Select "Edit".

Navigate to Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy.

If the "Enforce user logon restrictions" is not set to "Enabled", this is a finding.
#>

# PARTIAL
if ($Script:IsDomainController) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}