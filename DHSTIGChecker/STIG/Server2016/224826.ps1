<#
Rule Title: Windows Server 2016 must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.
Severity: medium
Vuln ID: V-224826
STIG ID: WN16-00-000090

Discussion:
Using a whitelist provides a configuration management method to allow the execution of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities.

The organization must identify authorized software programs and only permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.


Check Content:
This is applicable to unclassified systems. For other systems, this is NA.

Verify the operating system employs a deny-all, permit-by-exception policy to allow the execution of authorized software programs.

If an application whitelisting program is not in use on the system, this is a finding.

Configuration of whitelisting applications will vary by the program.

AppLocker is a whitelisting application built into Windows Server. A deny-by-default implementation is initiated by enabling any AppLocker rules within a category, only allowing what is specified by defined rules.

If AppLocker is used, perform the following to view the configuration of AppLocker:

Open "PowerShell".

If the AppLocker PowerShell module has not been imported previously, execute the following first:

Import-Module AppLocker

Execute the following command, substituting [c:\temp\file.xml] with a location and file name appropriate for the system:

Get-AppLockerPolicy -Effective -XML > c:\temp\file.xml

This will produce an xml file with the effective settings that can be viewed in a browser or opened in a program such as Excel for review.

Implementation guidance for AppLocker is available in the NSA paper "Application Whitelisting using Microsoft AppLocker" at the following link:

https://www.iad.gov/iad/library/ia-guidance/tech-briefs/application-whitelisting-using-microsoft-applocker.cfm

#>
return 'Not Reviewed'
