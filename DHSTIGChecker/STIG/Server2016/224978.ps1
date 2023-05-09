<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 5 Benchmark Date: 14 Nov 2022
Severity:   high
Vuln ID:    V-224978
Rule ID:    SV-224978r569186_rule
STIG ID:    WN16-DC-000150
Legacy:     V-73385; SV-88037
Rule Title: Directory data (outside the root DSE) of a non-public directory must be configured to prevent anonymous access.
Discussion:
To the extent that anonymous access to directory data (outside the root DSE) is permitted, read access control of the data is effectively disabled. If other means of controlling access (such as network restrictions) are compromised, there may be nothing else to protect the confidentiality of sensitive directory data.


Check Content:
This applies to domain controllers. It is NA for other systems.

Open "Command Prompt" (not elevated).

Run "ldp.exe".

From the "Connection menu", select "Bind".

Clear the User, Password, and Domain fields.

Select "Simple bind" for the Bind type and click "OK".

Confirmation of anonymous access will be displayed at the end:

res = ldap_simple_bind_s
Authenticated as: 'NT AUTHORITY\ANONYMOUS LOGON'

From the "Browse" menu, select "Search".

In the Search dialog, enter the DN of the domain naming context (generally something like "dc=disaost,dc=mil") in the Base DN field.

Clear the Attributes field and select "Run".

Error messages should display related to Bind and user not authenticated.

If attribute data is displayed, anonymous access is enabled to the domain naming context and this is a finding.

The following network controls allow the finding severity to be downgraded to a CAT II since these measures lower the risk associated with anonymous access.

Network hardware ports at the site are subject to 802.1x authentication or MAC address restrictions. 

Premise firewall or host restrictions prevent access to ports 389, 636, 3268, and 3269 from client hosts not explicitly identified by domain (.mil) or IP address.
#>

# PARTIAL
if ($Script:IsDomainController) {
    "Not Reviewed"
}
else {
    "Not Applicable"
}