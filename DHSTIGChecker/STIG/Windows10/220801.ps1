# UNCLASSIFIED
<#
STIG:       Microsoft Windows 10 Security Technical Implementation Guide :: Version 2, Release: 6 Benchmark Date: 11 May 2023
Severity:   medium
Vuln ID:    V-220801
Rule ID:    SV-220801r569187_rule
STIG ID:    WN10-CC-000039
Legacy:     V-72329; SV-86953
Rule Title: Run as different user must be removed from context menus.
Discussion:
The "Run as different user" selection from context menus allows the use of credentials other than the currently logged on user.  Using privileged credentials in a standard user session can expose those credentials to theft.  Removing this option from context menus helps prevent this from occurring.


Check Content:
If the following registry values do not exist or are not configured as specified, this is a finding.
The policy configures the same Value Name, Type and Value under four different registry paths.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Paths:  
\SOFTWARE\Classes\batfile\shell\runasuser\
\SOFTWARE\Classes\cmdfile\shell\runasuser\
\SOFTWARE\Classes\exefile\shell\runasuser\
\SOFTWARE\Classes\mscfile\shell\runasuser\

Value Name:  SuppressionPolicy

Type:  REG_DWORD
Value:  0x00001000 (4096)
#>

$Local:Results = @()
$Local:Paths = @(
    "HKLM:\SOFTWARE\Classes\batfile\shell\runasuser\",
    "HKLM:\SOFTWARE\Classes\cmdfile\shell\runasuser\",
    "HKLM:\SOFTWARE\Classes\exefile\shell\runasuser\",
    "HKLM:\SOFTWARE\Classes\mscfile\shell\runasuser\"
)

foreach ($Path in $Local:Paths) {
    $Params = @{
        Path          = "$Path"
        Name          = "SuppressionPolicy"
        ExpectedValue = 4096
    }
    $Local:Results += Compare-RegKeyValue @Params
}

if ($Local:Results -contains $false) {
    $false
}
else {
    $true
}