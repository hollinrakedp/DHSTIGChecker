# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220704
Rule ID:    SV-220704r859297_rule
STIG ID:    WN10-00-000032
Legacy:     V-94861; SV-104691
Rule Title: Windows 10 systems must use a BitLocker PIN with a minimum length of six digits for pre-boot authentication.
Discussion:
If data at rest is unencrypted, it is vulnerable to disclosure. Even if the operating system enforces permissions on data access, an adversary can remove non-volatile memory and read it directly, thereby circumventing operating system controls. Encrypting the data ensures that confidentiality is protected even when the operating system is not running. Pre-boot authentication prevents unauthorized users from accessing encrypted drives. Increasing the PIN length requires a greater number of guesses for an attacker.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

For virtual desktop implementations (VDIs) in which the virtual desktop instance is deleted or refreshed upon logoff, this is NA.

For Azure Virtual Desktop (AVD) implementations with no data at rest, this is NA.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\FVE\

Value Name: MinimumPIN
Type: REG_DWORD
Value: 0x00000006 (6) or greater
#>

if ($Script:isVDI) {
    if (!($Script:VDIPersist)) {
        Write-Verbose "Reason: Non-Persistent VDI"
        return "Not Applicable"
    }
}

$Params = @{
    Path          = "HKLM:"
    Name          = "\SOFTWARE\Policies\Microsoft\FVE\"
    ExpectedValue = 6
    Comparison = "ge"
}

Compare-RegKeyValue @Params