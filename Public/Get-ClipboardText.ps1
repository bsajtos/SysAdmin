

function Get-ClipboardText{
#version 2.0

[CmdletBinding()]
param (
	[switch]$Serverlist = $false
)


$clip = [windows.clipboard]::gettext()

#in case of SM9 format [servername (SID)] return only the servername
if ($Serverlist) {
    Add-Type -Assembly PresentationCore
    $regex = "[A-Za-z0-9/\\]*"
    $clip = $clip.Split("`n") | % {($_ | Select-String -Pattern $regex).matches.Groups[0].value | ? {$_ -ne ""}}  
}

return $clip

}
