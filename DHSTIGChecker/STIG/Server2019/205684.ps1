# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205684
Rule ID:    SV-205684r569188_rule
STIG ID:    WN19-00-000400
Legacy:     V-93395; SV-103481
Rule Title: Windows Server 2019 must have the Server Message Block (SMB) v1 protocol disabled on the SMB client.
Discussion:
SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB. MD5 is known to be vulnerable to a number of attacks such as collision and preimage attacks as well as not being FIPS compliant.


Check Content:
Different methods are available to disable SMBv1 on Windows Server 2019, if WN19-00-000380 is configured, this is NA.

If the following registry value is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Services\mrxsmb10\

Value Name: Start

Type: REG_DWORD
Value: 0x00000004 (4)
#>

# INCOMPLETE
return 'Not Reviewed'
