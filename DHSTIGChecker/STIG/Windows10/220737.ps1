<#
Rule Title: Administrative accounts must not be used with applications that access the Internet, such as web browsers, or with potential Internet sources, such as email.
Severity: high
Vuln ID: V-220737
STIG ID: WN10-00-000240

Discussion:
Using applications that access the Internet or have potential Internet sources using administrative privileges exposes a system to compromise. If a flaw in an application is exploited while running as a privileged user, the entire system could be compromised. Web browsers and email are common attack vectors for introducing malicious code and must not be run with an administrative account.

Since administrative accounts may generally change or work around technical restrictions for running a web browser or other applications, it is essential that policy requires administrative accounts to not access the Internet or use applications, such as email.

The policy should define specific exceptions for local service administration. These exceptions may include HTTP(S)-based tools that are used for the administration of the local system, services, or attached devices.

Technical means such as application whitelisting can be used to enforce the policy to ensure compliance.


Check Content:
Determine whether administrative accounts are prevented from using applications that access the Internet, such as web browsers, or with potential Internet sources, such as email, except as necessary for local service administration.

The organization must have a policy that prohibits administrative accounts from using applications that access the Internet, such as web browsers, or with potential Internet sources, such as email, except as necessary for local service administration. The policy should define specific exceptions for local service administration. These exceptions may include HTTP(S)-based tools that are used for the administration of the local system, services, or attached devices.

Technical measures such as the removal of applications or application whitelisting must be used where feasible to prevent the use of applications that access the Internet. 

If accounts with administrative privileges are not prevented from using applications that access the Internet or with potential Internet sources, this is a finding.

#>

#Incomplete
return "Not Reviewed"