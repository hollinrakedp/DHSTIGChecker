function Get-CurrentSecurityPolicySetting {
    [CmdletBinding()]
    param (
        [string]$Policy
    )
    
    begin {
        
    }
    
    process {
        $result = $CurrentSecPolicy["$Policy"]
        if ([string]::IsNullOrEmpty($result)) {
            "Policy not found"
        }
        else {
            $result
        }
    }
    
    end {
        
    }
}