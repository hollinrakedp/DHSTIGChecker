# UNCLASSIFIED
<#
STIG:       Microsoft Windows Server 2016 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-224949
Rule ID:    SV-224949r569186_rule
STIG ID:    WN16-CC-000420
Legacy:     V-73577; SV-88241
Rule Title: Attachments must be prevented from being downloaded from RSS feeds.
Discussion:
Attachments from RSS feeds may not be secure. This setting will prevent attachments from being downloaded from RSS feeds.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding.

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