# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-253283
Rule ID:    SV-253283r828933_rule
STIG ID:    WN11-00-000145
Legacy:     
Rule Title: Data Execution Prevention (DEP) must be configured to at least OptOut.
Discussion:
Attackers are constantly looking for vulnerabilities in systems and applications. Data Execution Prevention (DEP) prevents harmful code from running in protected memory locations reserved for Windows and other programs.


Check Content:
Verify the DEP configuration.
Open a command prompt (cmd.exe) or PowerShell with elevated privileges (Run as administrator).
Enter "BCDEdit /enum {current}". (If using PowerShell "{current}" must be enclosed in quotes.)
If the value for "nx" is not "OptOut", this is a finding.
(The more restrictive configuration of "AlwaysOn" would not be a finding.)
#>

switch ($Script:ComputerInfo.OsDataExecutionPreventionSupportPolicy) {
    OptOut { $true }
    AlwaysOn { $true }
    Default { $false }
}