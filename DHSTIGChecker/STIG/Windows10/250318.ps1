<#
Rule Title: PowerShell Transcription must be enabled on Windows 10.
Severity: medium
Vuln ID: V-250318
STIG ID: WN10-CC-000327

Discussion:
Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Enabling PowerShell Transcription will record detailed information from the processing of PowerShell commands and scripts. This can provide additional detail when malware has run on a system.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\

Value Name: EnableTranscripting

Value Type: REG_DWORD
Value: 1

#>

#Single Value Check
$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\"
    Name          = "EnableTranscripting"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params