# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224995
Rule ID:    SV-224995r852364_rule
STIG ID:    WN16-DC-000320
Legacy:     V-73629; SV-88293
Rule Title: Domain controllers must require LDAP access signing.
Discussion:
Unsigned network traffic is susceptible to man-in-the-middle attacks, where an intruder captures packets between the server and the client and modifies them before forwarding them to the client. In the case of an LDAP server, this means that an attacker could cause a client to make decisions based on false records from the LDAP directory. The risk of an attacker pulling this off can be decreased by implementing strong physical security measures to protect the network infrastructure. Furthermore, implementing Internet Protocol security (IPsec) authentication header mode (AH), which performs mutual authentication and packet integrity for Internet Protocol (IP) traffic, can make all types of man-in-the-middle attacks extremely difficult.

Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188


Check Content:
This applies to domain controllers. It is NA for other systems.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SYSTEM\CurrentControlSet\Services\NTDS\Parameters\

Value Name: LDAPServerIntegrity

Value Type: REG_DWORD
Value: 0x00000002 (2)
#>

# PARTIAL
if ($Script:IsDomainController) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}