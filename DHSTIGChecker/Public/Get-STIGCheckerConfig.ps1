function Get-STIGCheckerConfig {
    <#
    .SYNOPSIS
    Retreive a STIG Checker configuration file.

    .DESCRIPTION
    This function retreives the configuration file for the STIG environment.

    .NOTES
    Name         - Get-STIGCheckerConfig
    Version      - 0.1
    Author       - Darren Hollinrake
    Date Created - 2022-02-05
    Date Updated - 
    
    .PARAMETER Path
    The path to the configuration file for the system.

    #>

    [CmdletBinding()]
    param (
        [Parameter(
            ValueFromPipelineByPropertyName,
            Mandatory)]
        [string]$Path
    )
    
    if ((Test-Path $Path) -and ($Path -match '^*\.json')) {
        Get-Content "$Path" | ConvertFrom-Json
    }
    else {
        Write-Warning "The specified path is not valid. Please provide a valid config file path to import."
        return
    }
}