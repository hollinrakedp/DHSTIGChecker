# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   low
Vuln ID:    V-253447
Rule ID:    SV-253447r829425_rule
STIG ID:    WN11-SO-000085
Legacy:     
Rule Title: Caching of logon credentials must be limited.
Discussion:
The default Windows configuration caches the last logon credentials for users who log on interactively to a system. This feature is provided for system availability reasons, such as the user's machine being disconnected from the network or domain controllers being unavailable. Even though the credential cache is well-protected, if a system is attacked, an unauthorized individual may isolate the password to a domain user account using a password-cracking program and gain access to the domain.


Check Content:
This is the default configuration for this setting (10 logons to cache).

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\

Value Name: CachedLogonsCount

Value Type: REG_SZ
Value: 10 (or less)

This setting only applies to domain-joined systems, however, it is configured by default on all systems.
#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\"
    Name          = "CachedLogonsCount"
    ExpectedValue = 10
    Comparison    = "le"
}

Compare-RegKeyValue @Params