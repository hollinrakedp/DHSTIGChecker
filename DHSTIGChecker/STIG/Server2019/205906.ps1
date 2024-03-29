# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205906
Rule ID:    SV-205906r857326_rule
STIG ID:    WN19-MS-000050
Legacy:     V-93275; SV-103363
Rule Title: Windows Server 2019 must limit the caching of logon credentials to four or less on domain-joined member servers.
Discussion:
The default Windows configuration caches the last logon credentials for users who log on interactively to a system. This feature is provided for system availability reasons, such as the user's machine being disconnected from the network or domain controllers being unavailable. Even though the credential cache is well protected, if a system is attacked, an unauthorized individual may isolate the password to a domain user account using a password-cracking program and gain access to the domain.


Check Content:
This applies to member servers. For domain controllers and standalone or nondomain-joined systems, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\

Value Name:  CachedLogonsCount

Value Type:  REG_SZ
Value:  4 (or less)
#>

if (!($Script:IsDomainJoined)) {
    Write-Verbose "Reason: Standalone system"
    "Not Applicable"
}
elseif ($Script:IsDomainController) {
    Write-Verbose "Reason: Domain Controller"
    "Not Applicable"
}
else {
    $Params = @{
        Path          = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\"
        Name          = "CachedLogonsCount"
        ExpectedValue = 4
        Comparison    = "le"
    }

    Compare-RegKeyValue @Params
}