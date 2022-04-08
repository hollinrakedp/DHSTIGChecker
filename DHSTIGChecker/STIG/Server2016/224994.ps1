<#
Rule Title: Active Directory user accounts, including administrators, must be configured to require the use of a Common Access Card (CAC), Personal Identity Verification (PIV)-compliant hardware token, or Alternate Logon Token (ALT) for user authentication.
Severity: medium
Vuln ID: V-224994
STIG ID: WN16-DC-000310

Discussion:
Smart cards such as the CAC support a two-factor authentication technique. This provides a higher level of trust in the asserted identity than use of the username and password for authentication.

Satisfies: SRG-OS-000105-GPOS-00052, SRG-OS-000106-GPOS-00053, SRG-OS-000107-GPOS-00054, SRG-OS-000108-GPOS-00055, SRG-OS-000375-GPOS-00160


Check Content:
This applies to domain controllers. It is NA for other systems.

Open "PowerShell".

Enter the following:

"Get-ADUser -Filter {(Enabled -eq $True) -and (SmartcardLogonRequired -eq $False)} | FT Name"
("DistinguishedName" may be substituted for "Name" for more detailed output.)

If any user accounts, including administrators, are listed, this is a finding.

Alternately:

To view sample accounts in "Active Directory Users and Computers" (available from various menus or run "dsa.msc"):

Select the Organizational Unit (OU) where the user accounts are located. (By default, this is the Users node; however, accounts may be under other organization-defined OUs.)

Right-click the sample user account and select "Properties".

Select the "Account" tab.

If any user accounts, including administrators, do not have "Smart card is required for interactive logon" checked in the "Account Options" area, this is a finding.

#>
return 'Not Reviewed'
