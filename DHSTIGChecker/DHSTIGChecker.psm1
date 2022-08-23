$Public  = @( Get-ChildItem -Path $PSScriptRoot\Public\*.ps1 -ErrorAction SilentlyContinue )
$Private = @( Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue )

Foreach($script in @($Public + $Private)) {
    Try {
        . $script.fullname
    }
    Catch {
        Write-Error -Message "Failed to import function $($script.fullname): $_"
    }
}

$STIGRootPath = "$PSScriptRoot\STIG"

$Script:TabCompleteAvailableSTIGs = {(Get-ChildItem -Path $Script:STIGRootPath -Directory).Name}
Register-ArgumentCompleter -CommandName Invoke-STIGChecker -ParameterName Name -ScriptBlock $Script:TabCompleteAvailableSTIGs
Register-ArgumentCompleter -CommandName Get-STIGVulnInfo -ParameterName Name -ScriptBlock $Script:TabCompleteAvailableSTIGs

Export-ModuleMember -Function $Public.Basename