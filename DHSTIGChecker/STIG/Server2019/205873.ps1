<#
Rule Title: Windows Server 2019 must prevent attachments from being downloaded from RSS feeds.
Severity: medium
Vuln ID: V-205873
STIG ID: WN19-CC-000390

Discussion:
Attachments from RSS feeds may not be secure. This setting will prevent attachments from being downloaded from RSS feeds.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\

Value Name: DisableEnclosureDownload

Type: REG_DWORD
Value: 0x00000001 (1)

#>

$Params = @{
    Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\"
    Name          = "DisableEnclosureDownload"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params