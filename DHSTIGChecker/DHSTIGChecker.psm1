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

$TabCompleteAvailableSTIGs = {(Get-ChildItem -Path $STIGRootPath -Directory).Name}
Register-ArgumentCompleter -CommandName Invoke-STIGChecker -ParameterName Name -ScriptBlock $TabCompleteAvailableSTIGs

Export-ModuleMember -Function $Public.Basename