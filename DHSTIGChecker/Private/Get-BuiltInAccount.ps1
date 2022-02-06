function Get-BuiltInAccount {
    param (
        [Parameter(
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateSet('Administrator', 'Guest', 'DefaultAccount')]
        [string[]]$Account
    )
    begin { $LocalUsers = Get-LocalUser }
    process {
        foreach ($Name in $Account) {
            $obj = switch ($Name) {
                Administrator { $LocalUsers | Where-Object { $_.SID -like "S-1-5-*" -and $_.SID -like "*-500" } }
                Guest { $LocalUsers | Where-Object { $_.SID -like "S-1-5-*" -and $_.SID -like "*-501" } }
                DefaultAccount { $LocalUsers | Where-Object { $_.SID -like "S-1-5-*" -and $_.SID -like "*-503" } }
            }
            
            $obj | Add-Member -MemberType NoteProperty -Name Account -Value $Name -Force
            $obj
        }
    }
    end {}
    
}