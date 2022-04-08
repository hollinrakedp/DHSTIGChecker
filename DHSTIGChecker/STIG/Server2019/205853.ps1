<#
Rule Title: Windows Server 2019 FTP servers must be configured to prevent anonymous logons.
Severity: medium
Vuln ID: V-205853
STIG ID: WN19-00-000420

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
return 'Not Reviewed'
