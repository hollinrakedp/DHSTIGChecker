# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-225006
Rule ID:    SV-225006r569186_rule
STIG ID:    WN16-DC-000430
Legacy:     V-91779; SV-101881
Rule Title: The password for the krbtgt account on a domain must be reset at least every 180 days.
Discussion:
The krbtgt account acts as a service account for the Kerberos Key Distribution Center (KDC) service. The account and password are created when a domain is created and the password is typically not changed. If the krbtgt account is compromised, attackers can create valid Kerberos Ticket Granting Tickets (TGT).

The password must be changed twice to effectively remove the password history.Changing once, waiting for replication to complete and the amount of time equal to or greater than the maximum Kerberos ticket lifetime, and changing again reduces the risk of issues.


Check Content:
This requirement is applicable to domain controllers; it is NA for other systems.

Open "Windows PowerShell".

Enter "Get-ADUser krbtgt -Property PasswordLastSet".

If the "PasswordLastSet" date is more than 180 days old, this is a finding.
#>

# PARTIAL
if ($Script:IsDomainController) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}