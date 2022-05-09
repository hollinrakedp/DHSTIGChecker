<#
Rule Title: Windows Server 2019 must limit the caching of logon credentials to four or less on domain-joined member servers.
Severity: medium
Vuln ID: V-205906
STIG ID: WN19-MS-000050

Discussion:
The default Windows configuration caches the last logon credentials for users who log on interactively to a system. This feature is provided for system availability reasons, such as the user's machine being disconnected from the network or domain controllers being unavailable. Even though the credential cache is well protected, if a system is attacked, an unauthorized individual may isolate the password to a domain user account using a password-cracking program and gain access to the domain.


Check Content:
This applies to member servers. For domain controllers and standalone systems, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\

Value Name:  CachedLogonsCount

Value Type:  REG_SZ
Value:  4 (or less)

#>
if (!($Script:IsDomainJoined)) {
    Write-Verbose "This check does not apply: Reason - Standalone system"
    "Not Applicable"
}
elseif ($Script:IsDomainController) {
    Write-Verbose "This check does not apply: Reason - Domain Controller"
    "Not Applicable"
}
else {
    $Params = @{
        Path          = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\"
        Name          = "CachedLogonsCount"
        ExpectedValue = 10
        Comparison    = "le"
    }

    Compare-RegKeyValue @Params
}