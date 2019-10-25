function Set-ConsoleSize {
    [Cmdletbinding()]
    param (
        [Parameter(Position = 0)]
        [ValidateRange(120,480)]
        [Alias('W')]
        [Int32]$Width = 120,

        [Parameter(Position = 1)]
        [ValidateRange(200,5000)]
        [Alias('H')]
        [Int32]$Height = 3000
    )
    
    $current = $Host.UI.RawUI.BufferSize 
    
    $currentW = $current.width
    $currentH = $current.height

    Write-Verbose "Initial Size: $($currentW) x $($currentH)"

    if (!$Width) {$Width = $currentW}
    if (!$Height) {$Height = $currentH}

    Write-Verbose "Target Size: $($Width) x $($Height)"

    
    if (($Width -eq $currentW) -and ($Height -eq $currentH)) {
        Write-Verbose 'Initial and Target size is the same. Resize is not necessary'
        }
   
    else {
        #resize
        try {
            $Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size($Width, $Height)
            Write-Verbose "Console successfully resized to: $Width x $Height"
        }
    
        catch {
            Write-Error $Error[-1]
        }
    }


}