function Get-WhoWasLoggedIn {
<#
.Synopsis
    Returns who was logged in within a specific time interval on the server(s).

.Description
    Collects Logon and Logoff events from Security log, then processes them by grouping the events based on their LogonID
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
    used in combination with EndTime and Minutes paramater tospecify an exact time interval.
    Default value: n/a, is calculated within script based on parameters.

.PARAMETER EndTime
    DateTime object. Defines the timestamp till events will be gathered. Can be used together with Minutes paramater,
    but not with StartTime paramater.
    Default value: n/a, is calculated within script based on parameters

.PARAMETER Minutes
    Integer object. Defines how many minutes should be included from either StartTime (forwards) or EndTime (backwards)
    paramaters. Must be in rage 1 minutes - 1440 mins (1 day).
    Default value: 120 minutes (2 hours)

.PARAMETER ExcludeNoise
    Switch. When specifying this switch paramater, certain events will be excluded which are usually noise: services which run as system,
    network logins, etc.
    Default value: False
    
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
                    2019.10.26 (v1.2) - ExcludeNoise switch
                                      - User Initiated Logoffs events (4647) included
                                      - CBH update
                                      - Combine-Objects used
                                      
    Todo: - to use start and end but not minutes
          - proper sorting/grouping
          - ps1xml to format output
          - combine different pscustomobject into 1... private function needed for that

#>


[Cmdletbinding()]
Param (
    [Parameter(Position = 0)]
    [Alias('CN')]
    [String[]]
    $ComputerName = $env:computername,
        
    [Parameter()]
    [Validaterange(1,1440)]
    [Int]
    $Minutes = 120,
        
    [Parameter()]
    [ValidateScript({$_ -lt ([datetime]::Now)})]
    [DateTime]
    $StartTime,
        
    [Parameter()]
    [DateTime]
    $EndTime,

    [Parameter()]
    [Switch]
    $ExcludeNoise,

    [Parameter()]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty
)


BEGIN{

    #Determining Filter Criteria for event lookup times
    $now = [datetime]::Now
    
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

    #do not search in the future, search till present latest
    if ($To -gt $now) {$To = $now}
    
    
    Write-Host "Analysed Time Interval:`t" -NoNewline
        Write-Host "$From - $To" -ForegroundColor Cyan
	Write-Host "Target Server(s):`t`t" -NoNewline
        Write-Host $ComputerName -ForegroundColor Cyan

}

PROCESS {

    $ResultLogons = New-Object System.Collections.ArrayList($null)
    $ResultLogoffs = New-Object System.Collections.ArrayList($null)
    $ResultUILs = New-Object System.Collections.ArrayList($null)
    
    foreach ($cn in $ComputerName) {
        #collecting LOGON events
        try {
            $Events = Get-WinEvent -computername $cn -ErrorAction Stop -FilterHashtable @{
                LogName = 'Security';
                ID = 4624,4634,4647;
                StartTime = $From;
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
        $UserInitiatedLogoffs = $Events | Where-Object {$_.ID -eq 4647}
           
      
        #LOGON - 4624
        foreach ($tempLogon in $Logons) {
            
            $obj = $tempLogon | select MachineName, TimeCreated,ID, ProcessId, ThreadId 
            $eventXML = ([xml]$tempLogon.toxml()).Event.EventData.Data
            
            for ($i=0; $i -lt $eventxml.count; $i++) {  
                Add-Member -InputObject $obj -MemberType NoteProperty -Force `
                    -Name  $($eventxml[$i].name)`
                    -Value $($eventxml[$i].'#text')  
            }
            
            Add-Member -InputObject $obj -MemberType NoteProperty -Force -Name Message -Value 'An account was logged on'


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
        
        
        #LOGOFF - 4634
        foreach ($tempLogoff in $Logoffs) {
            
            $obj = $tempLogoff | select MachineName, TimeCreated, ID, ProcessId, ThreadId 
            $eventXML = ([xml]$tempLogoff.toxml()).Event.EventData.Data
            
            for ($i=0; $i -lt $eventxml.count; $i++) {  
                Add-Member -InputObject $obj -MemberType NoteProperty -Force `
                    -Name  $($eventxml[$i].name)`
                    -Value $($eventxml[$i].'#text')  
            }
            
            Add-Member -InputObject $obj -MemberType NoteProperty -Force -Name Message -Value 'An account was logged off'

            
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

        #USER INITIATED LOGOFF - 4647
        foreach ($tempUIL in $UserInitiatedLogoffs) {
            
            $obj = $tempUIL | select MachineName, TimeCreated, ID, ProcessId, ThreadId 
            $eventXML = ([xml]$tempUIL.toxml()).Event.EventData.Data
            
            for ($i=0; $i -lt $eventxml.count; $i++) {  
                Add-Member -InputObject $obj -MemberType NoteProperty -Force `
                    -Name  $($eventxml[$i].name)`
                    -Value $($eventxml[$i].'#text')  
            }
            
            Add-Member -InputObject $obj -MemberType NoteProperty -Force -Name Message -Value 'User initiated logoff'
 
            $resultUILs.add(($obj)) | Out-Null
            
        }
        
    }


    #combine logon and logoff events
    #$Result =  $ResultLogons + $resultLogoffs + $resultUILs
    $Result = Combine-Objects -object1 $ResultLogons -Object2 $ResultLogoffs
    $Result = Combine-Objects -Object1 $Result -Object2 $ResultUILs


    if ($ExcludeNoise) {
        $Result = $Result | Where-Object {$_.TargetUserName -notlike "$($env:computername)*"}

        #Services which run as SYSTEM
        $Result = $Result | Where-Object {$_.TargetUserName -notlike 'SYSTEM' -and $_.Logontype -notlike "5*"}
        
        #Network logons, usually: IIS, printers, shared folders
        $Result = $Result | Where-Object {$_.Logontype -notlike "3*"}
        
        #https://docs.microsoft.com/en-us/windows/win32/dwm/dwm-overview
        $Result = $Result | Where-Object {$_.TargetDomainName -ne 'Window Manager'}

    }

}


END {
    
    #return output
    $Result | sort TimeCreated | select MachineName, TimeCreated, Message, TargetUserName, LogonType, targetlogonid

    #cleanup
    [System.GC]::Collect()
}

}


Set-Alias -Name Get-WhoFuckedUp -Value Get-WhoWasLoggedIn
