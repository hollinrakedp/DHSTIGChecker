# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220697
Rule ID:    SV-220697r857178_rule
STIG ID:    WN10-00-000005
Legacy:     V-63319; SV-77809
Rule Title: Domain-joined systems must use Windows 10 Enterprise Edition 64-bit version.
Discussion:
Features such as Credential Guard use virtualization-based security to protect information that could be used in credential theft attacks if compromised. A number of system requirements must be met for Credential Guard to be configured and enabled properly. Virtualization-based security and Credential Guard are only available with Windows 10 Enterprise 64-bit version.


Check Content:
Verify domain-joined systems are using Windows 10 Enterprise Edition 64-bit version.

For standalone or nondomain-joined systems, this is NA.

Open "Settings".

Select "System", then "About".

If "Edition" is not "Windows 10 Enterprise", this is a finding.

If "System type" is not "64-bit operating system…", this is a finding.
#>

if ($Script:IsDomainJoined) {
    $Bit = $Script:ComputerInfo.OsArchitecture
    $ProductName = $Script:ComputerInfo.WindowsProductName
    if (($Bit -like "64-bit") -and ($ProductName -like "Windows 10 Enterpise")) {
        $true
    }
    else {
        $false
    }
}
else {
    Write-Verbose "This check does not apply: Reason - Not Domain-Joined"
    return "Not Applicable"
}