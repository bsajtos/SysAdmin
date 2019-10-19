
function Set-MaintenanceMode
{
<#
.Synopsis
   Sets Maintenance Mode on target servers for the specified duration.

.Description
   Sets Maintenance Mode on target servers for the specified duration. Script is based on an application eventlog entry generation.
   Background: After you have started your script a maintenance request will be sent to the system log. This entry causes a message 
   to be send from the OA to OML and OMi and set the maintenance mode for the affected server or CI and the desired time period. 
   On OMi every event will be processed and checked if it is supposed to handle the entries in the downtime list.
   If an event is received on OMi were the regarding CI is in Downtime / Maintenance Mode, the event will be suppressed, 
   no notification takes place and no ticket will be opened for it.

.PARAMETER Duration
   Integer value. Specifies the duration of the maintanance mode in minutes.
   Default value: 120 minutes

.PARAMETER Reason
   String type. You can specify the Reason why Maintenance Mode is necessary (e.g.:Reboot/CHM number)
   Default Value: Reboot

.PARAMETER Admin
   String type. You can spcify the admin name who initiated the Maintenance Mode configuration.
   Default value: Gets the user name of the person who is currently logged on to the Windows operating system

.PARAMETER ComputerName
	System.Array type parameter. It accepts array of target servers stored in variables, stored in a e.g: serverlist.txt files, or accepts lists.
	Default value is the computername in the environment variable (localhost).

.EXAMPLE
  C:\PS> Set-MaintenanceMode
  Maintenance mode was successfully set on server [Z2T1DEFMVLTX001] for 120 minute duration starting from 2017-04-11 14:56:35
 Description
 -----------
 This command will set Maintenance Mode locally with default parameters:
 -ComputerName: localhost
 -Reason: Reboot
 -Admin: username of who is invoking the script
 -Duration: 120 minutes

.EXAMPLE
 C:\PS> Set-MaintenanceMode -ComputerName z2t1defmvltx001 -Duration 60 -Reason C123456789
 Description
 -----------
 This command will set Maintenance Mode for 60 minutes on a server with a change number as a reason.

.EXAMPLE
 C:\PS> Set-MaintenanceMode -ComputerName z2t1defmvltx001 -Stop
 Description
 -----------
 This command will terminate previously configured Maintenance Mode on target server(s), if the activity ended sooner than originally planned.

.EXAMPLE
  C:\PS> $servers = get-content serverlist.txt
  C:\PS> Set-MaintenanceMode -ComputerName $servers -Duration 60 -Reason C123456789 -Admin BSAJTOS
 Description
 -----------
 This command will set Maintenance Mode for 60 minutes on multiple servers defined in $servers variable with a change number as a reason and in the name of the specified Administrator.

.EXTERNALHELP
https://mywiki.telekom.de/display/SYSMOW/Maintenance+Mode

#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)]
		[Alias('cn')]
		[system.array]$ComputerName = $env:computername,
		[Parameter(Mandatory = $false)]
		[Int32]$Duration = 120,
		[Parameter(Mandatory = $false)]
		[string]$Reason = "Reboot",
		[Parameter(Mandatory = $false)]
		[string]$Admin = $env:UserName,
		[Parameter(Mandatory = $false)]
		[switch]$Stop
	)
	
	foreach ($cn in $computername)
		{
		#check connection
		if ((Test-Connection -ComputerName $cn -Quiet -Count 2 -ErrorAction SilentlyContinue) -and (Test-WSMan -ComputerName $cn -ErrorAction SilentlyContinue))
			{
			#check if we want to set or terminate and existing maintanance
			#To stop the AdHoc Maintenance Mode before the configured time has expired you can send the same request with source=t_maintenance_stop
			if ($Stop)
			{
				try
				{
					Invoke-Command -Cn $cn -ErrorAction Stop -ScriptBlock {
						param ($Cn,
							$Duration,
							$Reason,
							$Admin)
						#create eventlog entry for terminating maintanance mode
						eventcreate /L application /T information /SO t_maintenance_stop /ID 1 /D "[t_maintenance_start mm_local,Reason:$Reason,Admin:$Admin,Duration:$Duration,Sub_Source:DC]" | Out-Null
					} -ArgumentList ($Cn, $Duration, $Reason, $Admin)
					$message = "Maintenance Mode was terminated on server [$($cn)]"
					$message
				}
				catch
				{
					Write-Warning "Maintenance mode was not terminated on [$($cn)]. Remote Management failed."
				}
			}
			
			else #if Stop parameter is not defined
			{
				try
				{
					Invoke-Command -Cn $cn -ErrorAction Stop -ScriptBlock {
						param ($Cn,
							$Duration,
							$Reason,
							$Admin)
						#create eventlog entry for maintanance mode
						eventcreate /L application /T information /SO t_maintenance_start /ID 1 /D "[t_maintenance_start mm_local,Reason:$Reason,Admin:$Admin,Duration:$Duration,Sub_Source:DC]" | Out-Null
						
						#check if eventlog entry creation was successfull, then collect some data
						$maintEvent = Get-WinEvent -ErrorAction SilentlyContinue -FilterHashtable @{ LogName = “Application”; ID = 1; ProviderName = "t_maintenance_start" } | select -First 1
						
						if (((Get-Date) - ($maintEvent.timecreated)).totalseconds -lt 30)
						{
							$message = "Maintenance mode was successfully set on server [$($cn)] for $($Duration) minute duration starting from $($maintEvent.timecreated.ToString("yyyy-MM-dd HH:mm:ss"))"
						}
						else { $message = "Maintenance mode configuration failed on server $($cn)." }
						
						#output
						$message
					} -ArgumentList ($Cn, $Duration, $Reason, $Admin)
				}
				catch
				{
					Write-Warning "Maintenance mode was not set on [$($cn)]. Remote Management failed."
				}
			}
		}
		else { Write-Warning "Maintenance mode was not set on [$($cn)]. Remote Management failed." }
	} #foreachend
}

