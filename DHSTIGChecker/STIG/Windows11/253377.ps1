# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253377
Rule ID:    SV-253377r829215_rule
STIG ID:    WN11-CC-000115
Legacy:     
Rule Title: Systems must at least attempt device authentication using certificates.
Discussion:
Using certificates to authenticate devices to the domain provides increased security over passwords. By default systems will attempt to authenticate using certificates and fall back to passwords if the domain controller does not support certificates for devices. This may also be configured to always use certificates for device authentication.


Check Content:
This requirement is applicable to domain-joined systems, for standalone systems this is NA.

The default behavior for "Support device authentication using certificate" is "Automatic".

If it exists and is configured with a value of "0", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\

Value Name: DevicePKInitEnabled
Value Type: REG_DWORD
Value: 1 (or if the Value Name does not exist)
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