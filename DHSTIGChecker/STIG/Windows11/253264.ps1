# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-253264
Rule ID:    SV-253264r828876_rule
STIG ID:    WN11-00-000045
Legacy:     
Rule Title: The Windows 11 system must use an antivirus program.
Discussion:
Malicious software can establish a base on individual desktops and servers. Employing an automated mechanism to detect this type of software will aid in elimination of the software from the operating system.


Check Content:
Verify an antivirus solution is installed on the system and in use. The antivirus solution may be bundled with an approved Endpoint Security Solution.

Verify if Microsoft Defender Antivirus is in use or enabled:

Open "PowerShell".

Enter "get-service | where {$_.DisplayName -Like "*Defender*"} | Select Status,DisplayName"

Verify third-party antivirus is in use or enabled:

Open "PowerShell".

Enter "get-service | where {$_.DisplayName -Like "*mcafee*"} | Select Status,DisplayName"

Enter "get-service | where {$_.DisplayName -Like "*symantec*"} | Select Status,DisplayName"

If there is no antivirus solution installed on the system, this is a finding.
#>

# PARTIAL
$AV = Get-Service -Name "WinDefend", "*mcafee*", "*symantec*" | Where-Object {$_.Status -eq 'Running'}
if ($AV.count -ge 1) {
    $true
}
else {
    $false
}