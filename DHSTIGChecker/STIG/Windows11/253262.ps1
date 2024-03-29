# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253262
Rule ID:    SV-253262r890447_rule
STIG ID:    WN11-00-000035
Legacy:     
Rule Title: The operating system must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.
Discussion:
Utilizing an allowlist provides a configuration management method for allowing the execution of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities.

The organization must identify authorized software programs and only permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as allowlisting.


Check Content:
This is applicable to unclassified systems.

Verify the operating system employs a deny-all, permit-by-exception policy to allow the execution of authorized software programs. This must include packaged apps such as the universal apps installed by default on systems.

If an application allowlisting program is not in use on the system, this is a finding.

Configuration of allowlisting applications will vary by the program.

AppLocker is an allowlisting application built into Windows 11 Enterprise. A deny-by-default implementation is initiated by enabling any AppLocker rules within a category, only allowing what is specified by defined rules.

If AppLocker is used, perform the following to view the configuration of AppLocker:
Run "PowerShell".

Execute the following command, substituting [c:\temp\file.xml] with a location and file name appropriate for the system:
Get-AppLockerPolicy -Effective -XML > c:\temp\file.xml

This will produce an xml file with the effective settings that can be viewed in a browser or opened in a program such as Excel for review.

Implementation guidance for AppLocker is available at the following link:

https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-policies-deployment-guide
#>

# Partial
if ($Script:IsClassified) {
    'Not Applicable'
}
else {
    "Not Reviewed"
}