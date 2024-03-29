# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224826
Rule ID:    SV-224826r890501_rule
STIG ID:    WN16-00-000090
Legacy:     V-73235; SV-87887
Rule Title: Windows Server 2016 must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.
Discussion:
Using an allowlist provides a configuration management method to allow the execution of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities.

The organization must identify authorized software programs and only permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as allowlisting.


Check Content:
Verify the operating system employs a deny-all, permit-by-exception policy to allow the execution of authorized software programs.

If an application allowlisting program is not in use on the system, this is a finding.

Configuration of allowlisting applications will vary by the program.

AppLocker is an allowlisting application built into Windows Server. A deny-by-default implementation is initiated by enabling any AppLocker rules within a category, only allowing what is specified by defined rules.

If AppLocker is used, perform the following to view the configuration of AppLocker:

Open "PowerShell".

If the AppLocker PowerShell module has not been imported previously, execute the following first:

Import-Module AppLocker

Execute the following command, substituting [c:\temp\file.xml] with a location and file name appropriate for the system:

Get-AppLockerPolicy -Effective -XML > c:\temp\file.xml

This will produce an xml file with the effective settings that can be viewed in a browser or opened in a program such as Excel for review.

Implementation guidance for AppLocker is available at the following link:

https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-policies-deployment-guide
#>

# PARTIAL
if ($Script:IsClassified) {
    'Not Applicable'
}
else {
    "Not Reviewed"
}