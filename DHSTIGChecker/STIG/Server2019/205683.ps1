# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205683
Rule ID:    SV-205683r569188_rule
STIG ID:    WN19-00-000390
Legacy:     V-93393; SV-103479
Rule Title: Windows Server 2019 must have the Server Message Block (SMB) v1 protocol disabled on the SMB server.
Discussion:
SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB. MD5 is known to be vulnerable to a number of attacks such as collision and preimage attacks as well as not being FIPS compliant.


Check Content:
Different methods are available to disable SMBv1 on Windows Server 2019, if WN19-00-000380 is configured, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\

Value Name: SMB1

Type: REG_DWORD
Value: 0x00000000 (0)
#>

# INCOMPLETE
return 'Not Reviewed'
