function Get-ClipboardText{
    #version 2.0

    [CmdletBinding()]
    param (
	    [switch]$AsServerlist = $false,
        [switch]$AsString = $false
    )

    Add-Type -Assembly PresentationCore
    $clip = [windows.clipboard]::gettext()


    #returns the clipboard as a long string
    if ($AsString) {
        return $clip
        break
    }


    #in case of SM9 format [servername (SID)] return only the servername in arrays
    if ($AsServerlist) {
    
        $regex = "[A-Za-z0-9/\\]*"
        $clip = $clip.Split("`n") | % {($_ | Select-String -Pattern $regex).matches.Groups[0].value | ? {$_ -ne ""}} 
        return $clip
        break
     
    }

    #default
    return $clip.Split("`n") | ? {$_ -ne ""}
    

}
