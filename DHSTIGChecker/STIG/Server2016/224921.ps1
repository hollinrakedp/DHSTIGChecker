# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224921
Rule ID:    SV-224921r857251_rule
STIG ID:    WN16-CC-000090
Legacy:     V-73509; SV-88161
Rule Title: Hardened UNC paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares.
Discussion:
Additional security requirements are applied to Universal Naming Convention (UNC) paths specified in hardened UNC paths before allowing access to them. This aids in preventing tampering with or spoofing of connections to these paths.


Check Content:
This requirement is applicable to domain-joined systems. For standalone or nondomain-joined systems, this is NA.

If the following registry values do not exist or are not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\

Value Name: \\*\NETLOGON
Value Type: REG_SZ
Value: RequireMutualAuthentication=1, RequireIntegrity=1

Value Name: \\*\SYSVOL
Value Type: REG_SZ
Value: RequireMutualAuthentication=1, RequireIntegrity=1

Additional entries would not be a finding.
#>

if (!($Script:IsDomainJoined)) {
    Write-Verbose "Reason: Not Domain-Joined"
    return "Not Applicable"
}

$Local:Results = @()
$Local:Names = '\\*\NETLOGON', '\\*\SYSVOL'

foreach ($_ in $Local:Names) {
    $Params = @{
        Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\"
        Name          = "$_"
        ExpectedValue = "RequireMutualAuthentication=1, RequireIntegrity=1"
    }
        
    $Local:Results += Compare-RegKeyValue @Params
}

if ($Local:Results -contains $false) {
    $false
}
else {
    $true
}