# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205853
Rule ID:    SV-205853r569188_rule
STIG ID:    WN19-00-000420
Legacy:     V-93223; SV-103311
Rule Title: Windows Server 2019 FTP servers must be configured to prevent anonymous logons.
Discussion:
The FTP service allows remote users to access shared files and directories. Allowing anonymous FTP connections makes user auditing difficult.

Using accounts that have administrator privileges to log on to FTP risks that the userid and password will be captured on the network and give administrator access to an unauthorized user.


Check Content:
If FTP is not installed on the system, this is NA.

Open "Internet Information Services (IIS) Manager".

Select the server.

Double-click "FTP Authentication".

If the "Anonymous Authentication" status is "Enabled", this is a finding.
#>

# INCOMPLETE
return 'Not Reviewed'
