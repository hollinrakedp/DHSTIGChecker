<#
Rule Title: Group Policy objects must be reprocessed even if they have not changed.
Severity: medium
Vuln ID: V-224925
STIG ID: WN16-CC-000150

Discussion:
Registry entries for group policy settings can potentially be changed from the required configuration. This could occur as part of troubleshooting or by a malicious process on a compromised system. Enabling this setting and then selecting the "Process even if the Group Policy objects have not changed" option ensures the policies will be reprocessed even if none have been changed. This way, any unauthorized changes are forced to match the domain-based group policy settings again.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\

Value Name: NoGPOListChanges

Type: REG_DWORD
Value: 0x00000000 (0)

#>

$Params = @{
    Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
    Name = "NoGPOListChanges"
    ExpectedValue = 0
}

Compare-RegKeyValue @Params