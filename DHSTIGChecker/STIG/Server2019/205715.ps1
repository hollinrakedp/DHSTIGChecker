# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205715
Rule ID:    SV-205715r857320_rule
STIG ID:    WN19-MS-000020
Legacy:     V-93519; SV-103605
Rule Title: Windows Server 2019 local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain-joined member servers.
Discussion:
A compromised local administrator account can provide means for an attacker to move laterally between domain systems.

With User Account Control enabled, filtering the privileged token for local administrator accounts will prevent the elevated privileges of these accounts from being used over the network.


Check Content:
This applies to member servers. For domain controllers and standalone or nondomain-joined systems, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System

Value Name:  LocalAccountTokenFilterPolicy

Type:  REG_DWORD
Value: 0x00000000 (0)

This setting may cause issues with some network scanning tools if local administrative accounts are used remotely. Scans should use domain accounts where possible. If a local administrative account must be used, temporarily enabling the privileged token by configuring the registry value to "1" may be required.
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
        Path          = "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
        Name          = "LocalAccountTokenFilterPolicy"
        ExpectedValue = 0
    }

    Compare-RegKeyValue @Params
}