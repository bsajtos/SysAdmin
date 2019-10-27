function Get-TimeDetails {
    
    $format = 'yyyy.MM.dd HH:mm:ss'
    $now = [datetime]::Now  
    $tz = [System.TimeZoneInfo]::Local

    #Extending the DateTime object with further Properties
    Add-Member -InputObject $now -MemberType NoteProperty -Name UTCTime     -Value $now.ToUniversalTime().ToString($format)
    Add-Member -InputObject $now -MemberType NoteProperty -Name LocalTime   -Value $now.ToLocalTime().ToString($format)
    Add-Member -InputObject $now -MemberType NoteProperty -Name ZoneID      -Value $([Regex]::Replace($tz.StandardName, '([A-Z])\w+\s*', '$1'))
    Add-Member -InputObject $now -MemberType NoteProperty -Name ZoneIDShort -Value $tz.StandardName

    #out
    $now

}

