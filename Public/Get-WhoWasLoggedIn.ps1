function Get-WhoWasLoggedIn {
<#
.Synopsis
    Returns who was logged in at a specific time interval on the server.

.Description
    Collects Logon and Logoff events from Security logs, then processes them by grouping the events based on their LogonID
    in a cronological order. It makes possible to easily follow session activity within a give time interval.
    Policies -> Windows Settings -> Security Settings -> Local Policies -> Audit Policy -> Logon/Logoff events must be enabled.

.PARAMETER ComputerName
    String array type parameter. It accepts array of target servers stored in variables, stored in a e.g: serverlist.txt files, or accepts lists.
	Default value is the computername in the environment variable (localhost).

.PARAMETER Credential
    PSCredential object. You can specify credentials to authenticate with a different user to execute the function.
    Default value is the current user's credentials.

.PARAMETER StartTime
    DateTime object. Defines the timestamp when events will be gathered from. Must not point to a future date. Can be
    used together with Minutes paramater, but not with EndTime paramater.
    Default value: n/a, is calculated within script based on parameters

.PARAMETER EndTime
    DateTime object. Defines the timestamp till events will be gathered. Can be used together with Minutes paramater,
    but not with StartTime paramater.
    Default value: n/a, is calculated within script based on parameters

.PARAMETER Minutes
    Integer object. Defines how many minutes should be included from either StartTime (forwards) or EndTime (backwards)
    paramaters. Must be in rage 1 minutes - 1440 mins (1 day).
    Default value: 120 minutes (2 hours)
    
.EXAMPLE
    C:\PS> Get-WhoWasLoggedIn
    Description
    -----------
    Without parameters defined, the function will search in the eventlog from the past 2 hours for Logon and Logoff messages.
    The collected events will be grouped and sorted by LogonIDs.

.EXAMPLE
    C:\PS> Get-WhoWasLoggedIn -ComputerName 'server1','server2' -From 2019.10.25T08:00:00 -Minutes 600
    Description
    -----------
    Logon and Logoff events will are gathered from multiple servers starting at the specified timestamp and ending 10 hours later.

.LINK
    https://

.NOTES
    Author:         Bela Sajtos
    Contact:        bela.sajtos@gmail.com 
    Release Notes:  2019.10.17 (v1.0) - include in module
                    2019.10.25 (v1.1) - facelift
                                      - paramatersets, param rework, renames
                                      - CBH
                                      
    Todo: - to use start and end but not minutes
          - use generic list XML [Collections.Generic.List[XML]]
          - validate if logon/logoff is enabled
          - include 'logon' and 'logoff'
          - proper sorting/grouping
          - ps1xml to format output

#>


    [Cmdletbinding(DefaultParameterSetName = 'Min')]
    Param (
        [Parameter(Position = 0)]
        [Alias('CN')]
        [String[]]
        $ComputerName = $env:computername,
        
        [Parameter(ParameterSetName='Start')]
        [Parameter(ParameterSetName='End')]
        [Parameter(ParameterSetName='Min')]
        [Validaterange(1,1440)]
        [Int]
        $Minutes = 120,
        
        [Parameter(ParameterSetName='Start')]
        [ValidateScript({$_ -lt (Get-Date)})]
        [DateTime]
        $StartTime,
        
        [Parameter(ParameterSetName='End')]
        [DateTime]
        $EndTime, 

        [Parameter()]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

BEGIN{

    #Determining Filter Criteria for event lookup times
    $now = Get-Date
    
    if ($StartTime -and $EndTime) {
        $From = $StartTime
        $To = $EndTime
        }
    elseif ($StartTime){
        $From = $StartTime
		$To = $From.AddMinutes($Minutes)
    }
    elseif ($EndTime) {
        $To = $EndTime
        $From = $To.AddMinutes(-$Minutes)
    }
    else {
        $From = $now.AddMinutes(-$Minutes)
        $To = $now
    }

    #do not search in the future, search maximum till present
    if ($To -gt $now) {$To = $now}
    
    
    Write-Host "Analysed Time Interval:`t" -NoNewline
        Write-Host "$From - $To" -ForegroundColor Cyan
	Write-Host "Target Server(s):`t`t" -NoNewline
        Write-Host $ComputerName -ForegroundColor Cyan

}

PROCESS {

    $ResultLogons = New-Object System.Collections.ArrayList($null)
    $resultLogoffs = New-Object System.Collections.ArrayList($null)

    foreach ($cn in $ComputerName) {
        #collecting LOGON events
        try {
            $Events = Get-WinEvent -computername $cn -ErrorAction Stop -FilterHashtable @{
                LogName = 'Security';`
                ID = 4624,4634; `
                StartTime = $From;`
                EndTime = $To
                }
        }
        
        catch {
            Write-Host "$cn : $($_.exception.message) Server will be skipped from further processing." -ForegroundColor Red
            continue
        }
        
        #seperating events due to different xml structures
        $Logons =  $Events | Where-Object {$_.ID -eq 4624}
        $Logoffs = $Events | Where-Object {$_.ID -eq 4634}
           
      
        
        foreach ($tempLogon in $Logons) {
            
            $obj = $tempLogon | select MachineName, TimeCreated,ID, ProcessId, ThreadId 
            $eventXML = ([xml]$tempLogon.toxml()).Event.EventData.Data
            
            for ($i=0; $i -lt $eventxml.count; $i++) {  
                Add-Member -InputObject $obj -MemberType NoteProperty -Force `
                    -Name  $($eventxml[$i].name)`
                    -Value $($eventxml[$i].'#text')  
            }
            
            #Modifying some values to be more userfriendly
            #http://techgenix.com/logon-types/
            switch ($obj.LogonType){
                1  { $obj.LogonType = '1:Undefined Logon type' }
                2  { $obj.LogonType = '2:Interactive' }
                3  { $obj.LogonType = '3:Network' }
                4  { $obj.LogonType = '4:Batch' }
                5  { $obj.LogonType = '5:Service' }
                6  { $obj.LogonType = '6:Proxy'}
                7  { $obj.LogonType = '7:Unlock' }
                8  { $obj.LogonType = '8:NetworkClearText' }
                9  { $obj.LogonType = '9:NewCredentials' }
                10 { $obj.LogonType = '10:RemoteInteractive' }
                11 { $obj.LogonType = '11:CachedInteractive' }
                12 { $obj.LogonType = '12:CachedRemoteInteractive'}
                13 { $obj.LogonType = '13:CachedUnlock'}
            default { $obj.LogonType = 'Unknown' }
            }
            
            #https://msdn.microsoft.com/en-us/library/cc704588.aspx
            switch ($obj.Status){
                '0xc000006e'  { $obj.Status = '0xc000006e (STATUS_ACCOUNT_RESTRICTION)' }
                '0xc000006d'  { $obj.Status = '0xc000006d (STATUS_LOGON_FAILURE)' }
                '0xc0000234'  { $obj.Status = '0xc0000234 (STATUS_ACCOUNT_LOCKED_OUT)' }
                '0xc0000193'  { $obj.Status = '0xc0000193 (STATUS_ACCOUNT_EXPIRED)' }
                '0xc0000022'  { $obj.Status = '0xc0000022 (STATUS_ACCESS_DENIED)' }
                '0xc00002ee'  { $obj.Status = '0xc00002ee (STATUS_UNFINISHED_CONTEXT_DELETED)' }
                '0XC0000224'  { $obj.Status = '0xc0000224 (STATUS_PASSWORD_MUST_CHANGE)' }
                '0xc000015b'  { $obj.Status = '0xc000015b (STATUS_LOGON_TYPE_NOT_GRANTED)' }
                '0xc0000133'  { $obj.Status = '0xc0000133 (STATUS_TIME_DIFFERENCE_AT_DC)' }
                default { $obj.Status }
            }
            
            #https://msdn.microsoft.com/en-us/library/cc704588.aspx
            switch ($obj.SubStatus){
                '0xc000006a'  { $obj.SubStatus = '0xc000006a (STATUS_WRONG_PASSWORD)' }
                '0xc000006f'  { $obj.SubStatus = '0xc000006f (STATUS_INVALID_LOGON_HOURS)' }
                '0xc0000071'  { $obj.SubStatus = '0xc0000071 (STATUS_PASSWORD_EXPIRED)' }
                '0xc0000072'  { $obj.SubStatus = '0xc0000072 (STATUS_ACCOUNT_DISABLED)' }
                '0x0'         { $obj.SubStatus = '0x0  (STATUS_SUCCESS)' }
                '0xc0000064'  { $obj.SubStatus = '0xc0000064 (STATUS_NO_SUCH_USER)' }
                '0xc0000022'  { $obj.SubStatus = '0xc0000022 (STATUS_ACCESS_DENIED)' }
                default { $obj.SubStatus }
            }
            
            #https://social.technet.microsoft.com/Forums/office/en-US/9eac1798-36da-4b57-8c7e-e01072765bd4/failure-reasons-eg-2313-in-id-4625?forum=winserversecurity
            switch ($obj.FailureReason){
                '%%2307'  { $obj.FailureReason = 'Account locked out' }
                '%%2305'  { $obj.FailureReason = 'The specified user account has expired' }
                '%%2304'  { $obj.FailureReason = 'An Error occured during Logon' }
                '%%2309'  { $obj.FailureReason = 'The specified accounts password has expired' }
                '%%2310'  { $obj.FailureReason = 'Account currently disabled' }
                '%%2311'  { $obj.FailureReason = 'Account logon time restriction violation' }
                '%%2312'  { $obj.FailureReason = 'User not allowed to logon at this computer' }
                '%%2313'  { $obj.FailureReason = 'Unknown user name or bad password' }
            default { $obj.FailureReason }
            }
            
            $ResultLogons.add(($obj)) | Out-Null
        }
        
        

        foreach ($tempLogoff in $Logoffs) {
            
            $obj = $tempLogoff | select MachineName, TimeCreated, ID, ProcessId, ThreadId 
            $eventXML = ([xml]$tempLogoff.toxml()).Event.EventData.Data
            
            for ($i=0; $i -lt $eventxml.count; $i++) {  
                Add-Member -InputObject $obj -MemberType NoteProperty -Force `
                    -Name  $($eventxml[$i].name)`
                    -Value $($eventxml[$i].'#text')  
            }
            
            #Modifying some values to be more userfriendly
            #http://techgenix.com/logon-types/
            switch ($obj.LogonType){
                1  { $obj.LogonType = '1:Undefined Logon type' }
                2  { $obj.LogonType = '2:Interactive' }
                3  { $obj.LogonType = '3:Network' }
                4  { $obj.LogonType = '4:Batch' }
                5  { $obj.LogonType = '5:Service' }
                6  { $obj.LogonType = '6:Proxy'}
                7  { $obj.LogonType = '7:Unlock' }
                8  { $obj.LogonType = '8:NetworkClearText' }
                9  { $obj.LogonType = '9:NewCredentials' }
                10 { $obj.LogonType = '10:RemoteInteractive' }
                11 { $obj.LogonType = '11:CachedInteractive' }
                12 { $obj.LogonType = '12:CachedRemoteInteractive'}
                13 { $obj.LogonType = '13:CachedUnlock'}
            default { $obj.LogonType = 'Unknown' }
            }
            
            $resultLogoffs.add(($obj)) | Out-Null
            
           
        }

        
    }
    

    #combine logon and logoff events
    $Result = $ResultLogons + $resultLogoffs 

}

END {
    
    #return output
    $Result | sort TargetLogonId
    [System.GC]::Collect()
}

}


Set-Alias -Name Get-WhoFuckedUp -Value Get-WhoWasLoggedIn
