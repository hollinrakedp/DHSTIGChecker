# UNCLASSIFIED
<#
STIG:       Microsoft Windows 11 Security Technical Implementation Guide :: Version 1, Release: 3 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-253407
Rule ID:    SV-253407r829305_rule
STIG ID:    WN11-CC-000295
Legacy:     
Rule Title: Attachments must be prevented from being downloaded from RSS feeds.
Discussion:
Attachments from RSS feeds may not be secure. This setting will prevent attachments from being downloaded from RSS feeds.


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