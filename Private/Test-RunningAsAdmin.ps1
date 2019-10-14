function Test-RunningAsAdmin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    #return bool
    ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
}

