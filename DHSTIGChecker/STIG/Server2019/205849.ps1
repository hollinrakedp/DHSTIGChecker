<#
Rule Title: Windows Server 2019 must be maintained at a supported servicing level.
Severity: high
Vuln ID: V-205849
STIG ID: WN19-00-000100

Discussion:
Systems at unsupported servicing levels will not receive security updates for new vulnerabilities, which leave them subject to exploitation. Systems must be maintained at a servicing level supported by the vendor with new security updates.


Check Content:
Open "Command Prompt".

Enter "winver.exe".

If the "About Windows" dialog box does not display "Microsoft Windows Server Version 1809 (Build 17763.xxx)" or greater, this is a finding.

Preview versions must not be used in a production environment.

#>
return 'Not Reviewed'
