# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224848
Rule ID:    SV-224848r857240_rule
STIG ID:    WN16-00-000330
Legacy:     V-73283; SV-87935
Rule Title: Windows Server 2016 must automatically remove or disable temporary user accounts after 72 hours.
Discussion:
If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be used to gain unauthorized access. To mitigate this risk, automated termination of all temporary accounts must be set upon account creation.

Temporary accounts are established as part of normal account activation procedures when there is a need for short-term accounts without the demand for immediacy in account activation.

If temporary accounts are used, the operating system must be configured to automatically terminate these types of accounts after a DoD-defined time period of 72 hours.

To address access requirements, many operating systems may be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements.


Check Content:
Review temporary user accounts for expiration dates.

Determine if temporary user accounts are used and identify any that exist. If none exist, this is NA.

Domain Controllers:

Open "PowerShell".

Enter "Search-ADAccount -AccountExpiring | FT Name, AccountExpirationDate".

If "AccountExpirationDate" has not been defined within 72 hours for any temporary user account, this is a finding.

Member servers and standalone or nondomain-joined systems:

Open "Command Prompt".

Run "Net user [username]", where [username] is the name of the temporary user account.

If "Account expires" has not been defined within 72 hours for any temporary user account, this is a finding.
#>

# INCOMPLETE
return 'Not Reviewed'
