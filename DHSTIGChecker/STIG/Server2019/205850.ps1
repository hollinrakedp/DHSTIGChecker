<#
Rule Title: Windows Server 2019 must use an anti-virus program.
Severity: high
Vuln ID: V-205850
STIG ID: WN19-00-000110

Discussion:
Malicious software can establish a base on individual desktops and servers. Employing an automated mechanism to detect this type of software will aid in elimination of the software from the operating system.


Check Content:
Verify an anti-virus solution is installed on the system. The anti-virus solution may be bundled with an approved host-based security solution.

If there is no anti-virus solution installed on the system, this is a finding.

Verify if Windows Defender is in use or enabled:

Open "PowerShell".

Enter “get-service | where {$_.DisplayName -Like "*Defender*"} | Select Status,DisplayName”

Verify if third-party anti-virus is in use or enabled:

Open "PowerShell".

Enter "get-service | where {$_.DisplayName -Like "*mcafee*"} | Select Status,DisplayName”

Enter "get-service | where {$_.DisplayName -Like "*symantec*"} | Select Status,DisplayName”


#>
return 'Not Reviewed'
