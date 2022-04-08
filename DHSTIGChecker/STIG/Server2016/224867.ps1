<#
Rule Title: Windows Server 2016 must have the number of allowed bad logon attempts configured to three or less.
Severity: medium
Vuln ID: V-224867
STIG ID: WN16-AC-000020

Discussion:
The account lockout feature, when enabled, prevents brute-force password attacks on the system. The higher this value is, the less effective the account lockout feature will be in protecting the local system. The number of bad logon attempts must be reasonably small to minimize the possibility of a successful password attack while allowing for honest errors made during normal user logon.


Check Content:
Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy.

If the "Account lockout threshold" is "0" or more than "3" attempts, this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas SecurityPolicy /CFG C:\Path\FileName.Txt

If "LockoutBadCount" equals "0" or is greater than "3" in the file, this is a finding.

#>
return 'Not Reviewed'
