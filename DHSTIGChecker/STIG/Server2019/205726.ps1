<#
Rule Title: Windows Server 2019 directory service must be configured to terminate LDAP-based network connections to the directory server after five minutes of inactivity.
Severity: low
Vuln ID: V-205726
STIG ID: WN19-DC-000160

Discussion:
The failure to terminate inactive network connections increases the risk of a successful attack on the directory server. The longer an established session is in progress, the more time an attacker has to hijack the session, implement a means to passively intercept data, or compromise any protections on client access. For example, if an attacker gains control of a client computer, an existing (already authenticated) session with the directory server could allow access to the directory. The lack of confidentiality protection in LDAP-based sessions increases exposure to this vulnerability.


Check Content:
This applies to domain controllers. It is NA for other systems.

Open an elevated "Command Prompt" (run as administrator).

Enter "ntdsutil".

At the "ntdsutil:" prompt, enter "LDAP policies".

At the "ldap policy:" prompt, enter "connections".

At the "server connections:" prompt, enter "connect to server [host-name]"
(where [host-name] is the computer name of the domain controller).

At the "server connections:" prompt, enter "q".

At the "ldap policy:" prompt, enter "show values". 

If the value for MaxConnIdleTime is greater than "300" (5 minutes) or is not specified, this is a finding.

Enter "q" at the "ldap policy:" and "ntdsutil:" prompts to exit.

Alternately, Dsquery can be used to display MaxConnIdleTime:

Open "Command Prompt (Admin)".
Enter the following command (on a single line).

dsquery * "cn=Default Query Policy,cn=Query-Policies,cn=Directory Service, cn=Windows NT,cn=Services,cn=Configuration,dc=[forest-name]" -attr LDAPAdminLimits 

The quotes are required and dc=[forest-name] is the fully qualified LDAP name of the domain being reviewed (e.g., dc=disaost,dc=mil).

If the results do not specify a "MaxConnIdleTime" or it has a value greater than "300" (5 minutes), this is a finding.

#>
return 'Not Reviewed'
