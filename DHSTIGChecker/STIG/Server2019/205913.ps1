<#
Rule Title: Windows Server 2019 must not allow anonymous SID/Name translation.
Severity: high
Vuln ID: V-205913
STIG ID: WN19-SO-000210

Discussion:
Allowing anonymous SID/Name translation can provide sensitive information for accessing a system. Only authorized users must be able to perform such translations.


Check Content:
Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options.

If the value for "Network access: Allow anonymous SID/Name translation" is not set to "Disabled", this is a finding.

#>
return 'Not Reviewed'
