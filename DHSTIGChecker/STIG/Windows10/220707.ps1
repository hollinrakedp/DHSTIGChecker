# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-220707
Rule ID:    SV-220707r793194_rule
STIG ID:    WN10-00-000045
Legacy:     V-63351; SV-77841
Rule Title: The Windows 10 system must use an anti-virus program.
Discussion:
Malicious software can establish a base on individual desktops and servers. Employing an automated mechanism to detect this type of software will aid in elimination of the software from the operating system.


Check Content:
Verify an anti-virus solution is installed on the system and in use. The anti-virus solution may be bundled with an approved Endpoint Security Solution.

Verify if Windows Defender is in use or enabled:

Open "PowerShell".

Enter “get-service | where {$_.DisplayName -Like "*Defender*"} | Select Status,DisplayName”

Verify third-party antivirus is in use or enabled:

Open "PowerShell".

Enter “get-service | where {$_.DisplayName -Like "*mcafee*"} | Select Status,DisplayName”

Enter “get-service | where {$_.DisplayName -Like "*symantec*"} | Select Status,DisplayName”

If there is no anti-virus solution installed on the system, this is a finding.
#>

# PARTIAL
$AV = Get-Service -Name "WinDefend", "*mcafee*", "*symantec*" | Where-Object {$_.Status -eq 'Running'}
if ($AV.count -ge 1) {
    $true
}
else {
    $false
}