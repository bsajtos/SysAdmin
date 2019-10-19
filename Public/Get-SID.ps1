

function Get-SID {
<#
.Synopsis
    Returns the SID of the server stored in files or registry.
.Description
    Returns the SID of the server stored in tsi_system_info.cfg file or registry
.PARAMETER ComputerName
	String array type parameter. It accepts array of target servers stored in variables, stored in a e.g: serverlist.txt files, or accepts lists.
	Default value is the computername in the environment variable.
.EXAMPLE
 C:\PS> Get-SID
 Description
 -----------
 bla
.EXAMPLE
 C:\PS> 
 Description
 -----------
 bla
.NOTES
 Release Notes: 2019.10.17 - Facelift/rework
 Todo: - pssession
       - registry query
#>

	[CMDletbinding()]
	param (
		[Parameter(Mandatory = $false, Position = 1)]
		[ValidateNotNullOrEmpty()]
        [Alias('CN')]
		[string[]]$ComputerName = $env:COMPUTERNAME
	)
	
    

	$Result = @()
	foreach ($Server in $ComputerName)
	{
		if (Test-Connection -ComputerName $Server -Count 2 -Quiet -ErrorAction SilentlyContinue)
		{
				
			$tsi_file = "\\$Server\C`$\Windows\System32\drivers\etc\epmf\tsi_system_info.cfg"
				
			if (Test-Path $tsi_file)
			{
				$SID = (Get-Content "\\$Server\C`$\Windows\System32\drivers\etc\epmf\tsi_system_info.cfg")[0].replace("system_id=", "").trim()
			}
			else
			{
				$SID = "tsi file is not available!"
			}
								
			$Temp = New-Object System.Management.Automation.PSObject
			$Temp | Add-Member -MemberType NoteProperty -Name Server -Value $Server.toupper()
			$Temp | Add-Member -MemberType NoteProperty -Name SID -Value $SID
			$Temp | Add-Member -MemberType NoteProperty -Name SM9_Format -Value ($Server + " (" + $SID + ")")
			$Result += $Temp
							
		}
		else
		{
			Write-Host "$Server is not reachable, manual check is necessary!" -ForegroundColor Yellow
			$SID = "unreachable"
			$Temp = New-Object System.Management.Automation.PSObject
			$Temp | Add-Member -MemberType NoteProperty -Name Server -Value $Server.toupper()
			$Temp | Add-Member -MemberType NoteProperty -Name SID -Value $SID
			$Temp | Add-Member -MemberType NoteProperty -Name SM9_Format -Value $null
			$Result += $Temp
		}
			
	}
	$Result | Sort-Object -Property SID, Server | Format-Table -AutoSize
		
	$Result | % { $Maintanance_Format += $_.Server.tolower() + "," }
	Write-Host "Serverlist for Maintenance mode:" -ForegroundColor Magenta
	$Maintanance_Format
	
}

