function Get-STIGVulnInfo {
    [CmdletBinding(DefaultParameterSetName = 'Query')]
    param (
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName)]
            [ValidateScript({
                if ($_ -in (& $Script:TabCompleteAvailableSTIGs)) {
                    $true
                }
                else {
                    throw "The supplied value `'$_`' is invalid. Valid values: $((& $Script:TabCompleteAvailableSTIGs) -join ', ')"
                }
            })]
        [string]$Name,
        [Parameter(
            Mandatory,
            ParameterSetName = 'Query',
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [string[]]$ID,
        [Parameter(
            ParameterSetName = 'ShowAll',
            ValueFromPipelineByPropertyName)]
        [switch]$All
    )
    
    begin {
        try {
            $STIGInfo = Import-Csv -Path "$STIGRootPath\$Name\data.csv"
            $defaultDisplaySet = 'Vuln ID', 'Severity', 'Rule Title'
            $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet', [string[]]$defaultDisplaySet)
            $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)
            $STIGInfo | Add-Member MemberSet PSStandardMembers $PSStandardMembers
        }
        catch {
            Write-Warning "Unable to find the STIG vulnerability information file."
            return
        } 
    }
    
    process {
        switch ($PSCmdlet.ParameterSetName) {
            Query {
                $Results = @()
                foreach ($item in $ID) {
                    $Results += $STIGInfo | Where-Object { ($_.'Vuln ID' -match $item) -or ($_.Legacy -match $item) }
                }
            }

            ShowAll {
                $Results = $STIGInfo
            }
        }
        if ($Results.count -ge 1) {
            $Results
        }
        else {
            Write-Output "No match was found."
        }
    }
    
    end {
    }
}