<#
Rule Title: Software certificate installation files must be removed from Windows Server 2016.
Severity: medium
Vuln ID: V-224842
STIG ID: WN16-00-000270

Discussion:
Use of software certificates and their accompanying installation files for end users to access resources is less secure than the use of hardware-based certificates.


Check Content:
Search all drives for *.p12 and *.pfx files.

If any files with these extensions exist, this is a finding.

This does not apply to server-based applications that have a requirement for .p12 certificate files or Adobe PreFlight certificate files. Some applications create files with extensions of .p12 that are not certificate installation files. Removal of non-certificate installation files from systems is not required. These must be documented with the ISSO.

#>

$CertFiles = Get-ChildItem -Path $Env:SystemDrive\ -Recurse -Include *.p12, *.pfx -File -ErrorAction SilentlyContinue
if ($CertFiles) {
    Write-Verbose "This check is Open: Reason - Certificate Files Found"
    Write-Verbose "Found the following certificate files: `n$($CertFiles.FullName)"
    $false
}
else {
    $true
}