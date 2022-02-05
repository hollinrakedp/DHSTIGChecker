function Get-DeviceGuard {
    [CmdletBinding()]
    param (
        
    )
    
    begin {
        
    }
    
    process {
        $psobj = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -Verbose:$false
        $defaultDisplaySet = 'AvailableSecurityProperties', 'RequiredSecurityProperties', 'VirtualizationBasedSecurityStatus', 'SecurityServicesRunning'
            $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet', [string[]]$defaultDisplaySet)
            $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)
            $psobj | Add-Member MemberSet PSStandardMembers $PSStandardMembers
            $psobj
    }
    
    end {
        
    }
}