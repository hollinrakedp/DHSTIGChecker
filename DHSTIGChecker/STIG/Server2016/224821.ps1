# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   high
Vuln ID:    V-224821
Rule ID:    SV-224821r569186_rule
STIG ID:    WN16-00-000040
Legacy:     V-73225; SV-87877
Rule Title: Administrative accounts must not be used with applications that access the Internet, such as web browsers, or with potential Internet sources, such as email.
Discussion:
Using applications that access the Internet or have potential Internet sources using administrative privileges exposes a system to compromise. If a flaw in an application is exploited while running as a privileged user, the entire system could be compromised. Web browsers and email are common attack vectors for introducing malicious code and must not be run with an administrative account.

Since administrative accounts may generally change or work around technical restrictions for running a web browser or other applications, it is essential that policy require administrative accounts to not access the Internet or use applications such as email.

The policy should define specific exceptions for local service administration. These exceptions may include HTTP(S)-based tools that are used for the administration of the local system, services, or attached devices.

Whitelisting can be used to enforce the policy to ensure compliance.


Check Content:
Determine whether organization policy, at a minimum, prohibits administrative accounts from using applications that access the Internet, such as web browsers, or with potential Internet sources, such as email, except as necessary for local service administration.

If it does not, this is a finding.

The organization may use technical means such as whitelisting to prevent the use of browsers and mail applications to enforce this requirement.
#>

# INCOMPLETE
return 'Not Reviewed'
