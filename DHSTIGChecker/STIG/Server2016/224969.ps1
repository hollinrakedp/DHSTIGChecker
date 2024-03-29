# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224969
Rule ID:    SV-224969r852344_rule
STIG ID:    WN16-DC-000060
Legacy:     V-73367; SV-88019
Rule Title: The computer clock synchronization tolerance must be limited to 5 minutes or less.
Discussion:
This setting determines the maximum time difference (in minutes) that Kerberos will tolerate between the time on a client's clock and the time on a server's clock while still considering the two clocks synchronous. In order to prevent replay attacks, Kerberos uses timestamps as part of its protocol definition. For timestamps to work properly, the clocks of the client and the server need to be in sync as much as possible.

Satisfies: SRG-OS-000112-GPOS-00057, SRG-OS-000113-GPOS-00058


Check Content:
This applies to domain controllers. It is NA for other systems.

Verify the following is configured in the Default Domain Policy.

Open "Group Policy Management".

Navigate to "Group Policy Objects" in the Domain being reviewed (Forest >> Domains >> Domain).
 
Right-click on the "Default Domain Policy".

Select "Edit".

Navigate to Computer Configuration >> Policies >> Windows Settings >> Security Settings >> Account Policies >> Kerberos Policy.

If the "Maximum tolerance for computer clock synchronization" is greater than "5" minutes, this is a finding.
#>

# PARTIAL
if ($Script:IsDomainController) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}