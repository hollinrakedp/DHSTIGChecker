<#
Rule Title: The time service must synchronize with an appropriate DoD time source.
Severity: low
Vuln ID: V-224862
STIG ID: WN16-00-000450

Discussion:
The Windows Time Service controls time synchronization settings. Time synchronization is essential for authentication and auditing purposes. If the Windows Time Service is used, it must synchronize with a secure, authorized time source. Domain-joined systems are automatically configured to synchronize with domain controllers. If an NTP server is configured, it must synchronize with a secure, authorized time source.


Check Content:
Review the Windows time service configuration.

Open an elevated "Command Prompt" (run as administrator).

Enter "W32tm /query /configuration".

Domain-joined systems (excluding the domain controller with the PDC emulator role):

If the value for "Type" under "NTP Client" is not "NT5DS", this is a finding.

Other systems:

If systems are configured with a "Type" of "NTP", including standalone systems and the domain controller with the PDC Emulator role, and do not have a DoD time server defined for "NTPServer", this is a finding.

To determine the domain controller with the PDC Emulator role:

Open "PowerShell".

Enter "Get-ADDomain | FT PDCEmulator".

#>
return 'Not Reviewed'
