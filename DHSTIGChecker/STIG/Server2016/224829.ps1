# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-224829
Rule ID:    SV-224829r569237_rule
STIG ID:    WN16-00-000120
Legacy:     V-73241; SV-87893
Rule Title: The Windows Server 2016 system must use an anti-virus program.
Discussion:
Malicious software can establish a base on individual desktops and servers. Employing an automated mechanism to detect this type of software will aid in elimination of the software from the operating system.


Check Content:
Verify an anti-virus solution is installed on the system. The anti-virus solution may be bundled with an approved host-based security solution.

If there is no anti-virus solution installed on the system, this is a finding.

Verify if Windows Defender is in use or enabled:

Open "PowerShell".

Enter "get-service | where {$_.DisplayName -Like "*Defender*"} | Select Status,DisplayName”

Verify if third-party anti-virus is in use or enabled:

Open "PowerShell".

Enter "get-service | where {$_.DisplayName -Like "*mcafee*"} | Select Status,DisplayName”

Enter "get-service | where {$_.DisplayName -Like "*symantec*"} | Select Status,DisplayName”
#>

$AV = Get-Service -Name "WinDefend", "*mcafee*", "*symantec*" | Where-Object {$_.Status -eq 'Running'}
if ($AV.count -ge 1) {
    $true
}
else {
    $false
}