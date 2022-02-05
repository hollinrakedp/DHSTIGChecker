function Get-ADSIGroupSID {
    [CmdletBinding()]
    param (
        [Parameter(
            Position = 0,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [String]$sAMAccountName
    )
    
    begin {}
    
    process {
        $ADSISearcher = [adsisearcher]"(&(objectCategory=group)(sAMAccountName=$sAMAccountName))"
        $Result = $ADSISearcher.FindOne().GetDirectoryEntry()
        $BinarySID = $Result.ObjectSid.Value
        (New-Object System.Security.Principal.SecurityIdentifier($BinarySID,0)).Value
    }
    
    end {}
}