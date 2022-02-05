function Test-RegKeyValueExists {
    <#
    .SYNOPSIS
    Tests if a registry key value exists.

    .DESCRIPTION
    This function checks to see if the specified Registry Key Value exists. It will return True if the Key Value exists and False if it does not.

    .NOTES
    Name         - Test-RegKeyValueExists
    Version      - 0.1
    Author       - Darren Hollinrake
    Date Created - 2022-01-16
    Date Updated - 

    .PARAMETER Path
    The path to the registry key. It should begin with 'HKCU:\' or 'HKLM:\'

    .PARAMETER Name
    The name of the registry key of which is being confirmed as existing.

    .EXAMPLE
    Test-RegKeyValueExists -Path 'HKLM:\SYSTEM\State\DateTime' -Name 'NTP Enabled'
    true

    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Name
    )

    if (!(Test-Path -Path $Path -PathType Container) ) {
        Write-Verbose "The Path does not exist."
        return $false
    }

    $Properties = Get-ItemProperty -Path $Path 
    if (! $Properties ) {
        return $false
    }

    $Member = Get-Member -InputObject $Properties -Name $Name
    if ( $Member ) {
        return $true
    }
    else {
        return $false
    }

}