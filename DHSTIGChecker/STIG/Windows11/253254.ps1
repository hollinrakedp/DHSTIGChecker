# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253254
Rule ID:    SV-253254r828846_rule
STIG ID:    WN11-00-000005
Legacy:     
Rule Title: Domain-joined systems must use Windows 11 Enterprise Edition 64-bit version.
Discussion:
Features such as Credential Guard use virtualization-based security to protect information that could be used in credential theft attacks if compromised. There are a number of system requirements that must be met in order for Credential Guard to be configured and enabled properly. Virtualization-based security and Credential Guard are only available with Windows 11 Enterprise 64-bit version.


Check Content:
Verify domain-joined systems are using Windows 11 Enterprise Edition 64-bit version.

For standalone systems, this is NA.

Open "Settings".

Select "System", then "About".

If "Edition" is not "Windows 11 Enterprise", this is a finding.

If "System type" is not "64-bit operating system...", this is a finding.
#>

if ($Script:IsDomainJoined) {
    $Bit = $Script:ComputerInfo.OsArchitecture
    $ProductName = $Script:ComputerInfo.WindowsProductName
    if (($Bit -like "64-bit") -and ($ProductName -like "Windows 11 Enterpise")) {
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