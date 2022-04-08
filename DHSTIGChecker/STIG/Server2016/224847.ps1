<#
Rule Title: Windows  Server 2016 must employ automated mechanisms to determine the state of  system components with regard to flaw remediation using the following  frequency: continuously, where Endpoint Security Solution (ESS) is  used; 30 days, for any additional internal network scans not covered by ESS; and annually, for external scans by Computer Network Defense  Service Provider (CNDSP).
Severity: medium
Vuln ID: V-224847
STIG ID: WN16-00-000320

Discussion:
Without the use of automated mechanisms to scan for security flaws on a continuous and/or periodic basis, the operating system or other system components may remain vulnerable to the exploits presented by undetected software flaws. The operating system may have an integrated solution incorporating continuous scanning using ESS and periodic scanning using other tools.


Check Content:
Verify DoD-approved ESS software is installed and properly operating. Ask the site ISSM for documentation of the ESS software installation and configuration.

If the ISSM is not able to provide a documented configuration for an installed ESS or if the ESS software is not properly maintained or used, this is a finding.

Note: Example of documentation can be a copy of the site's CCB approved Software Baseline with version of software noted or a memo from the ISSM stating current ESS software and version.

#>
return 'Not Reviewed'
