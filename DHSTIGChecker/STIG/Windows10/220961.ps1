<#
Rule Title: The Change the system time user right must only be assigned to Administrators and Local Service and NT SERVICE\autotimesvc.
Severity: medium
Vuln ID: V-220961
STIG ID: WN10-UR-000035

Discussion:
Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Change the system time" user right can change the system time, which can impact authentication, as well as affect time stamps on event log entries.

The NT SERVICE\autotimesvc is added in v1909 cumulative update. 


Check Content:
Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Change the system time" user right, this is a finding:

Administrators
LOCAL SERVICE
NT SERVICE\autotimesvc is added in v1909 cumulative update.

#>

$GrantedPrivilege = ($Script:CurrentSecPolicy.SeSystemtimePrivilege -split ',').trimstart('*')

$Allowed = @($Script:SIDLocalGroup.Administrators)
if ($Script:ComputerInfo.WindowsVersion -ge 1909) {
    $Allowed += (New-Object System.Security.Principal.NTAccount("NT Service\autotimesvc")).Translate([System.Security.Principal.SecurityIdentifier]).value 
}


$Local:Results = @()

foreach ($ID in $GrantedPrivilege) {
    $Local:Results += if ($Allowed -contains $ID ) {
        $true
    }
    else {
        $false
    }
}

if ($Local:Results -contains $false) {
    $false
}
else {
    $true
}