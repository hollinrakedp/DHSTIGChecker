# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220945
Rule ID:    SV-220945r569187_rule
STIG ID:    WN10-SO-000250
Legacy:     V-63819; SV-78309
Rule Title: User Account Control must, at minimum, prompt administrators for consent on the secure desktop.
Discussion:
User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting configures the elevation requirements for logged on administrators to complete a task that requires raised privileges.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: ConsentPromptBehaviorAdmin

Value Type: REG_DWORD
Value: 2 (Prompt for consent on the secure desktop)
#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
    Name          = "ConsentPromptBehaviorAdmin"
    ExpectedValue = 2
}

Compare-RegKeyValue @Params