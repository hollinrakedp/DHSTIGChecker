<#
Rule Title: Windows 10 systems must be maintained at a supported servicing level.
Severity: high
Vuln ID: V-220706
STIG ID: WN10-00-000040

Discussion:
Windows 10 is maintained by Microsoft at servicing levels for specific periods of time to support Windows as a Service. Systems at unsupported servicing levels or releases will not receive security updates for new vulnerabilities which leaves them subject to exploitation.

New versions with feature updates are planned to be released on a semi-annual basis with an estimated support timeframe of 18 to 30 months depending on the release. Support for previously released versions has been extended for Enterprise editions.

A separate servicing branch intended for special purpose systems is the Long-Term Servicing Channel (LTSC, formerly Branch - LTSB) which will receive security updates for 10 years but excludes feature updates.


Check Content:
Run "winver.exe".

If the "About Windows" dialog box does not display:

"Microsoft Windows Version 1909 (OS Build 18363.0)"

or greater, this is a finding.

Note: Microsoft has extended support for previous versions providing critical and important updates for Windows 10 Enterprise.

Microsoft scheduled end of support dates for current Semi-Annual Channel versions:

v1909 - 10 May 2022
v2004 - 14 December 2021
v20H2 � 9 May 2023

No preview versions will be used in a production environment.

Special-purpose systems using the Long-Term Servicing Branch\Channel (LTSC\B) may be at the following versions, which is not a finding:

v1507 (Build 10240)
v1607 (Build 14393)
v1809 (Build 17763)

#>

$EndOfSupport = switch ($Script:ComputerInfo.WindowsVersion) {
    1709 { Get-Date -Date "03-Oct-2020" }
    1803 { Get-Date -Date "11-May-2021" }
    1809 { Get-Date -Date "11-May-2021" }
    1903 { Get-Date -Date "08-Dec-2020" }
    1909 { Get-Date -Date "10-May-2022"}
    2004 { Get-Date -Date "14-Dec-2021" }
    2009 { Get-Date -Date "09-May-2023" }
    21H1 { Get-Date -Date "13-Dec-2022" }
    21H2 { Get-Date -Date "11-Jun-2024" }
    Default { 
        Write-Verbose "No match found."
        return 'Not Reviewed'
    }
}

(Get-Date) -lt $EndOfSupport