<#
Rule Title: Attachments must be prevented from being downloaded from RSS feeds.
Severity: medium
Vuln ID: V-220853
STIG ID: WN10-CC-000295

Discussion:
Attachments from RSS feeds may not be secure.  This setting will prevent attachments from being downloaded from RSS feeds.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\

Value Name: DisableEnclosureDownload

Value Type: REG_DWORD
Value: 1

#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\"
    Name          = "DisableEnclosureDownload"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params