# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   low
Vuln ID:    V-253296
Rule ID:    SV-253296r877038_rule
STIG ID:    WN11-00-000260
Legacy:     
Rule Title: The Windows 11 time service must synchronize with an appropriate DoD time source.
Discussion:
The Windows Time Service controls time synchronization settings. Time synchronization is essential for authentication and auditing purposes. If the Windows Time Service is used, it must synchronize with a secure, authorized time source. Domain-joined systems are automatically configured to synchronize with domain controllers. If an NTP server is configured, it must synchronize with a secure, authorized time source.


Check Content:
Review the Windows time service configuration.

Open an elevated "Command Prompt" (run as administrator).

Enter "W32tm /query /configuration".

Domain-joined systems (excluding the domain controller with the PDC emulator role):

If the value for "Type" under "NTP Client" is not "NT5DS", this is a finding.
#>

# INCOMPLETE
return 'Not Reviewed'
