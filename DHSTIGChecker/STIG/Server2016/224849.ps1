<#
Rule Title: Windows Server 2016 must automatically remove or disable emergency accounts after the crisis is resolved or within 72 hours.
Severity: medium
Vuln ID: V-224849
STIG ID: WN16-00-000340

Discussion:
Emergency administrator accounts are privileged accounts established in response to crisis situations where the need for rapid account activation is required. Therefore, emergency account activation may bypass normal account authorization processes. If these accounts are automatically disabled, system maintenance during emergencies may not be possible, thus adversely affecting system availability.

Emergency administrator accounts are different from infrequently used accounts (i.e., local logon accounts used by system administrators when network or normal logon/access is not available). Infrequently used accounts are not subject to automatic termination dates. Emergency accounts are accounts created in response to crisis situations, usually for use by maintenance personnel. The automatic expiration or disabling time period may be extended as needed until the crisis is resolved; however, it must not be extended indefinitely. A permanent account should be established for privileged users who need long-term maintenance accounts.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements.


Check Content:
Determine if emergency administrator accounts are used and identify any that exist. If none exist, this is NA.

If emergency administrator accounts cannot be configured with an expiration date due to an ongoing crisis, the accounts must be disabled or removed when the crisis is resolved.

If emergency administrator accounts have not been configured with an expiration date or have not been disabled or removed following the resolution of a crisis, this is a finding.

Domain Controllers:

Open "PowerShell".

Enter "Search-ADAccount –AccountExpiring | FT Name, AccountExpirationDate".

If "AccountExpirationDate" has been defined and is not within 72 hours for an emergency administrator account, this is a finding.

Member servers and standalone systems:

Open "Command Prompt".

Run "Net user [username]", where [username] is the name of the emergency account.

If "Account expires" has been defined and is not within 72 hours for an emergency administrator account, this is a finding.

#>
return 'Not Reviewed'
