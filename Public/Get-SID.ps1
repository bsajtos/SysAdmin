

function Get-SID
{
	[CMDletbinding()]
	param (
		[Parameter(Mandatory = $false, Position = 1)]
		[ValidateNotNullOrEmpty()]
		[System.Array]$ComputerName = $env:COMPUTERNAME
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

