# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220818
Rule ID:    SV-220818r857191_rule
STIG ID:    WN10-CC-000115
Legacy:     V-63627; SV-78117
Rule Title: Systems must at least attempt device authentication using certificates.
Discussion:
Using certificates to authenticate devices to the domain provides increased security over passwords.  By default systems will attempt to authenticate using certificates and fall back to passwords if the domain controller does not support certificates for devices.  This may also be configured to always use certificates for device authentication.


Check Content:
This requirement is applicable to domain-joined systems. For standalone or nondomain-joined systems, this is NA.

The default behavior for "Support device authentication using certificate" is "Automatic".

If the registry value name below does not exist, this is not a finding.

If it exists and is configured with a value of "1", this is not a finding.

If it exists and is configured with a value of "0", this is a finding.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\

Value Name:  DevicePKInitEnabled
Value Type:  REG_DWORD
Value:  1 (or if the Value Name does not exist)
#>

if (!($Script:IsDomainJoined)) {
    Write-Verbose "Reason: Not Domain-Joined"
    return "Not Applicable"
}

$Params = @{
    Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\"
    Name = "DevicePKInitEnabled"
    ExpectedValue = 1
}

if (!(Test-RegKeyValueExists -Path $Params.Path -Name $Params.Name)) {
    return $true
}

Compare-RegKeyValue @Params