# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220946
Rule ID:    SV-220946r890441_rule
STIG ID:    WN10-SO-000251
Legacy:     V-102627; SV-111577
Rule Title: Windows 10 must use multifactor authentication for local and network access to privileged and nonprivileged accounts.
Discussion:
Without the use of multifactor authentication, the ease of access to privileged and nonprivileged functions is greatly increased. 

All domain accounts must be enabled for multifactor authentication with the exception of local emergency accounts. 

Multifactor authentication requires using two or more factors to achieve authentication.

Factors include: 

1) Something a user knows (e.g., password/PIN);

2) Something a user has (e.g., cryptographic identification device, token); and

3) Something a user is (e.g., biometric).

A privileged account is defined as an information system account with authorizations of a privileged user.

Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the internet).

Local access is defined as access to an organizational information system by a user (or process acting on behalf of a user) communicating through a direct connection without the use of a network.

The DoD CAC with DoD-approved PKI is an example of multifactor authentication.

Satisfies: SRG-OS-000106-GPOS-00053, SRG-OS-000107-GPOS-00054, SRG-OS-000108-GPOS-00055


Check Content:
If the system is a member of a domain, this is Not Applicable.

If one of the following settings does not exist and is not populated, this is a finding: 

Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Calais\Readers
Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Calais\SmartCards
#>

# INCOMPLETE
return 'Not Reviewed'
