# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-253382
Rule ID:    SV-253382r829230_rule
STIG ID:    WN11-CC-000155
Legacy:     
Rule Title: Solicited Remote Assistance must not be allowed.
Discussion:
Remote assistance allows another user to view or take control of the local session of a user. Solicited assistance is help that is specifically requested by the local user. This may allow unauthorized parties access to the resources on the computer.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: fAllowToGetHelp
 
Value Type: REG_DWORD
Value: 0
#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
    Name = "fAllowToGetHelp"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params