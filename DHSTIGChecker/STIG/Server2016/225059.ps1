<#
Rule Title: Windows Server 2016 must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing.
Severity: medium
Vuln ID: V-225059
STIG ID: WN16-SO-000430

Discussion:
This setting ensures the system uses algorithms that are FIPS-compliant for encryption, hashing, and signing. FIPS-compliant algorithms meet specific standards established by the U.S. Government and must be the algorithms used for all OS encryption functions.

Satisfies: SRG-OS-000033-GPOS-00014, SRG-OS-000478-GPOS-00223


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\

Value Name: Enabled

Value Type: REG_DWORD
Value: 0x00000001 (1)
 
Clients with this setting enabled will not be able to communicate via digitally encrypted or signed protocols with servers that do not support these algorithms. Both the browser and web server must be configured to use TLS; otherwise. the browser will not be able to connect to a secure site.

#>
return 'Not Reviewed'
