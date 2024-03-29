# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253367
Rule ID:    SV-253367r829185_rule
STIG ID:    WN11-CC-000066
Legacy:     
Rule Title: Command line data must be included in process creation events.
Discussion:
Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Enabling "Include command line data for process creation events" will record the command line information with the process creation events in the log. This can provide additional detail when malware has run on a system.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\

Value Name: ProcessCreationIncludeCmdLine_Enabled

Value Type: REG_DWORD
Value: 1
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\"
    Name = "ProcessCreationIncludeCmdLine_Enabled"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params