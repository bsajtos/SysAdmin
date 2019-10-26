
function Get-FailedLogins {
<#
.SYNOPSIS
    Collects "Account failed to log on" events from Security log with optional analysis.

.DESCRIPTION
    Collects events with eventID 4625 (Account failed to log on) from Security Log, then provides the output and
    optional summary statistics in a userfriendly way.

.PARAMETER Minutes
    Integer object. Defines how many minutes should be included from either StartTime (forwards) or EndTime (backwards)
    paramaters. Must be in rage 1 minutes - 1440 mins (1 day).
    Default value: 60 minutes (1 hour)

.PARAMETER StartTime
    DateTime object. Defines the timestamp when events will be gathered from. Must not point to a future date. Can be
    used in combination with EndTime and Minutes paramater tospecify an exact time interval.
    Default value: n/a, is calculated within script based on parameters.

.PARAMETER EndTime
    DateTime object. Defines the timestamp till events will be gathered. Can be used together with Minutes paramater,
    but not with StartTime paramater.
    Default value: n/a, is calculated within script based on parameters

.PARAMETER ComputerName
    String Array type parameter. 
    It accepts array of target servers stored in variables, stored in a e.g: serverlist.txt files, or accepts listing.
    Default value is the computername in the environment variable.

.PARAMETER Analyse
    Switch parameter. With this optional parameter a basic evaluation can be executed which might point to the most probable
    problems.

.EXAMPLE
    C:\PS> Get-FailedLogins

    Description
    -----------
    This command will collect account failed to log on events (with eventID 4625) from the last 1 hour by default
    when no other filter criteria is defined. Events are then parsed, and the output will list responsible accounts
    and the number of the failed login attempts, descending.

.EXAMPLE
    C:\PS> Get-FailedLogins -Minutes 30

    Description
    -----------
    This command will collect account failed to log on events (with eventID 4625) from the past 30 minutes.
    Events are then parsed, and the output will list responsible accounts and the number of the failed login attempts.

.EXAMPLE
    C:\PS> Get-FailedLogins -Minutes 30 -OutGridview

    Description
    -----------
    This command will collect account failed to log on events (with eventID 4625) from the past 30 minutes.
    With the OutGridview switch defined, output will be shown in a new window if PowerShell ISE is installed on the server
    Events are then parsed, and the output will list responsible accounts and the number of the failed login attempts, descending.

.EXAMPLE   
    C:\PS> Get-FailedLogins -From 2017-02-01T10:54:10 -To 2017-02-01T10:55:00

    Description
    -----------
    This command will collect account failed to log on events (with eventID 4625) between the defined dates.
    Input parameters must be DateTime type in a Sortable DateTime Pattern (YYYY-MM-DDTHH:MM:SS) format. For reference see output of command 'Get-Date -f s'
    Events are then parsed, and the output will list responsible accounts and the number of the failed login attempts, descending.

.EXAMPLE
    C:\PS> Get-FailedLogins -ComputerName SME8010 -Minutes 30  -OutGridview
    C:\PS> Get-FailedLogins -ComputerName SME8010,SME8011,SME8012,SME8013  -Minutes 30 -OutGridview
    C:\PS> Get-FailedLogins -ComputerName $servers  -Minutes 30 -OutGridview

    Description
    -----------
    This command will collect account failed to log on events (with eventID 4625) from the past 30 minutes from one or more target servers.
    With the OutGridview switch defined, output will be shown in a new window if PowerShell ISE is installed on the server
    Events are then parsed, and the output will list responsible accounts and the number of the failed login attempts, descending.

.LINK
    GitHub
    -
    https://msdn.microsoft.com/en-us/library/windows/desktop/aa386907(v=vs.85).aspx
    https://www.vmware.com/pdf/vmware-tools-cli.pdf

.NOTES
    Version:        1.0
    Author:         Bela Sajtos
    Contact:        bela.sajtos@gmail.com 
    Release Notes:
        v1.0 (2017.12.12) - Function finalization and release
        v1.1 (2017.12.13) - Rework the function to use RunSpaces
        v1.2 (2019.10.26) - include in module
                          - facelift, little rework
    Todo: -CBH update




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
    $Minutes = 60,
        
    [Parameter()]
    [ValidateScript({$_ -lt ([datetime]::Now)})]
    [DateTime]
    $StartTime,
        
    [Parameter()]
    [DateTime]
    $EndTime,

    [Parameter()]
    [Switch]
    $Analyse,

    [Parameter()]
    [ValidateRange(1, 64)]
    [Int]
    $ThreadLimit = $env:NUMBER_OF_PROCESSORS,

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


    #region scriptblock will be executed in paralell RunSpace Threads
    $ScriptBlock = {
        param (
            [Parameter()]
            [string]
            $CompName,

            [Parameter()]
            [DateTime]
            $StartTime,

            [Parameter()]
            [DateTime]
            $EndTime
        )

        $SubResult = New-Object System.Collections.ArrayList($null)

        $tempevents = Get-WinEvent -ComputerName $CompName -ErrorAction Stop -FilterHashtable @{
            LogName = 'Security';
            ID = 4625;
            StartTime = $StartTime;
            EndTime = $EndTime
        }

        foreach ($tempevent in $tempevents) {
            $obj = $tempevent | select -Property MachineName, TimeCreated, ProcessId, ThreadId 
            $eventXML = ([xml]$tempevent.toxml()).Event.EventData.Data

            #add all of the XML properties to the base event object
            for ($i=0; $i -lt $eventxml.count; $i++) { 
                Add-Member -InputObject $obj -MemberType NoteProperty -Force `
                -Name $($eventxml[$i].name)`
                -Value $($eventxml[$i].'#text') 
            }

            #mapping human-readable message to the most frequent numerical codes observerd in my environment
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

            switch ($obj.Status){
            '0xc000006d' {$obj.Status = '0xc000006d (STATUS_LOGON_FAILURE)'}
            '0xc000006e' {$obj.Status = '0xc000006e (STATUS_ACCOUNT_RESTRICTION)'}
            '0xc0000234' {$obj.Status = '0xc0000234 (STATUS_ACCOUNT_LOCKED_OUT)'}
            '0xc0000022' {$obj.Status = '0xc0000022 (STATUS_ACCESS_DENIED)'}
            '0xc0000193' {$obj.Status = '0xc0000193 (STATUS_ACCOUNT_EXPIRED)'}
            '0xc00002ee' {$obj.Status = '0xc00002ee (STATUS_UNFINISHED_CONTEXT_DELETED)'}
            '0XC0000224' {$obj.Status = '0xc0000224 (STATUS_PASSWORD_MUST_CHANGE)'}
            '0xc000015b' {$obj.Status = '0xc000015b (STATUS_LOGON_TYPE_NOT_GRANTED)'}
            '0xc0000133' {$obj.Status = '0xc0000133 (STATUS_TIME_DIFFERENCE_AT_DC)'}
            }

            switch ($obj.SubStatus){
            '0xc000006a' {$obj.SubStatus = '0xc000006a (STATUS_WRONG_PASSWORD)'}
            '0xc0000072' {$obj.SubStatus = '0xc0000072 (STATUS_ACCOUNT_DISABLED)'}
            '0xc0000064' {$obj.SubStatus = '0xc0000064 (STATUS_NO_SUCH_USER)'}
            '0xc0000071' {$obj.SubStatus = '0xc0000071 (STATUS_PASSWORD_EXPIRED)'}
            '0x0'        {$obj.SubStatus = '0x0 (STATUS_SUCCESS)'}
            '0xc000006f' {$obj.SubStatus = '0xc000006f (STATUS_INVALID_LOGON_HOURS)'}
            '0xc0000022' {$obj.SubStatus = '0xc0000022 (STATUS_ACCESS_DENIED)'}
            '0x80090325' {$obj.SubStatus = '0x80090325 (SEC_E_UNTRUSTED_ROOT)'}
            '0xc0000193' {$obj.SubStatus = '0xc0000193 (STATUS_ACCOUNT_EXPIRED)'}
            }

            switch ($obj.FailureReason){
            '%%2313' {$obj.FailureReason = 'Unknown user name or bad password'}
            '%%2307' {$obj.FailureReason = 'Account locked out'}
            '%%2305' {$obj.FailureReason = 'The specified user account has expired'}
            '%%2304' {$obj.FailureReason = 'An Error occured during Logon'}
            '%%2309' {$obj.FailureReason = 'The specified accounts password has expired'}
            '%%2310' {$obj.FailureReason = 'Account currently disabled'}
            '%%2311' {$obj.FailureReason = 'Account logon time restriction violation'}
            '%%2312' {$obj.FailureReason = 'User not allowed to logon at this computer'}
            }

        #Collecting the captured and slightly modified events
        [void]$SubResult.add($obj)
        }
        #returning the result of the scriptblock
        $SubResult
    }
    #endregion

}

PROCESS {


    #region Runspace creation, progress tracking and extracting information
    #RUNSPACE POOL creation

    $Results = New-Object System.Collections.ArrayList($null)

    $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $ThreadLimit)
    $RunspacePool.Open()
    $Jobs = New-Object System.Collections.ArrayList($null)


    foreach ($cn in $ComputerName) {
        $Job = [powershell]::Create().AddScript($ScriptBlock).AddArgument($cn).AddArgument($From).AddArgument($To)
        $Job.RunspacePool = $RunspacePool
        [void]$Jobs.Add($(New-Object PSObject -Property @{
            Computer = $cn
            Pipe = $Job
            Result = $Job.BeginInvoke()
            }))
    }

    #Wait for all threads to complete
    do {
        Start-Sleep -Seconds 1
    }
    while ($Jobs.Result.IsCompleted -contains $false)


    #Collecting results of RS jobs
    foreach ($Job in $Jobs) {
        $Results.AddRange($($Job.Pipe.EndInvoke($Job.Result)))
        $Job.Pipe.Dispose()
    }
    #endregion

}

END {

    #if 'Analyse' is defined, display Basic statistics just to the console, then return the result object 
    #'Basic statistics' will not be sent to out stream as return value
    if ($Analyse -and $Results){
        Write-Host "$('-'*119)" -ForegroundColor Cyan
        Write-Host 'Basic stastics (TOP10s):'
        Write-Host "$('-'*119)" -ForegroundColor Cyan

        Write-Host "Failed login attempt(s): $($Results.Count). Per Target:" -NoNewline
        Write-Host ($Results | Group-Object Machinename -NoElement | 
        Sort-Object Count -Descending | 
        Select-Object -First 10 |
        Format-Table -HideTableHeaders -AutoSize | 
        Out-String).trimend()

        Write-Host "`nFailed login attempt(s) per Target UserName:" -NoNewline
        Write-Host ($Results | Group-Object TargetUserName -NoElement | 
        Sort-Object Count -Descending | 
        Select-Object @{n='DisplayName';e={$((([adsisearcher]"(&(objectCategory=person)(objectClass=User)(samaccountname=$($_.TargetUserName)))").FindAll()).properties.displayname)}} -First 10 |
        Format-Table -HideTableHeaders -AutoSize | 
        Out-String).trimend()

        Write-Host "`nFailed login attempt(s) per Source Workstation Name:" -NoNewline
        Write-Host ($Results | Group-Object WorkStationName -NoElement | 
        Sort-Object Count -Descending | 
        Select-Object -First 10 |
        Format-Table -HideTableHeaders | 
        Out-String).trimend()

        Write-Host "`nFailed login attempt(s) per Source IP:" -NoNewline
        Write-Host ($Results | Group-Object IPAddress -NoElement | 
        Sort-Object Count -Descending | 
        Select-Object -First 10 |
        Format-Table -HideTableHeaders | 
        Out-String).trimend()

        Write-Host "`nFailed login attempt(s) per Logon Type:" -NoNewline
        Write-Host ($Results | Group-Object LogonType -NoElement | 
        Sort-Object Count -Descending | 
        Select-Object -First 10 |
        Format-Table -HideTableHeaders -AutoSize | 
        Out-String).trimend()

        Write-Host "`nFailed login attempt(s) per Caller Process:" -NoNewline
        Write-Host ($Results | Group-Object ProcessName -NoElement | 
        Sort-Object Count -Descending | 
        Select-Object -First 10 |
        Format-Table -HideTableHeaders -AutoSize | 
        Out-String).trimend()
    
        Write-Host "$('-'*119)" -ForegroundColor Cyan

    }

    #always return the whole result object
    return $Results

}

}


