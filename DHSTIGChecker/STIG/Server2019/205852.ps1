# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-205852
Rule ID:    SV-205852r569188_rule
STIG ID:    WN19-00-000240
Legacy:     V-93221; SV-103309
Rule Title: Windows Server 2019 must have software certificate installation files removed.
Discussion:
Use of software certificates and their accompanying installation files for end users to access resources is less secure than the use of hardware-based certificates.


Check Content:
Search all drives for *.p12 and *.pfx files.

If any files with these extensions exist, this is a finding.

This does not apply to server-based applications that have a requirement for .p12 certificate files or Adobe PreFlight certificate files. Some applications create files with extensions of .p12 that are not certificate installation files. Removal of non-certificate installation files from systems is not required. These must be documented with the ISSO.
#>

$CertFiles = Get-ChildItem -Path $Env:SystemDrive\ -Recurse -Include *.p12, *.pfx -File -ErrorAction SilentlyContinue
if ($CertFiles) {
    Write-Verbose "Reason: Certificate Files Found"
    Write-Verbose "Found the following certificate files: `n$($CertFiles.FullName)"
    $false
}
else {
    $true
}