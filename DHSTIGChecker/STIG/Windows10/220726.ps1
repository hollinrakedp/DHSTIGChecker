# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-220726
Rule ID:    SV-220726r851966_rule
STIG ID:    WN10-00-000145
Legacy:     V-68845; SV-83439
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