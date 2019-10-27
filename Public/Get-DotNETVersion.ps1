function Get-DotNETVersion {
<#
.SYNOPSIS
    Retrieves .NET version.

.DESCRIPTION
    Retrieves .NET version based on processing information stored in registry entries.

.PARAMETER ComputerName
    String Array type parameter.
    Default Value: localhost
    Specifies remote target(s) for Query.


.PARAMETER Credential
    PSCredential type parameter.
    Default Value: empty credential (current credential with current session)
    
.PARAMETER ThrottleLimit
    Int type parameter.
    Default Value: 32, valid values between: 1-64
    Specifies how many PSsessions can coexist at once.

.EXAMPLE
    C:\PS> Get-DotNETVersion $servers

    TargetMachine   DotNETVersion                                              
    -------------   -------------                                              
    Z2T1DEFMVLA151  {2.0.50727.5420, 3.0.30729.5420, 3.5.30729.5420, 4.5.50938}
    Z2T1DEFMVLA150  {2.0.50727.5420, 3.0.30729.5420, 3.5.30729.5420, 4.5.50938}
    Z2T1DEFMVLA165  {2.0.50727.5420, 3.0.30729.5420, 3.5.30729.5420, 4.5.50938}
    Z2T1DEFMPLD001  {2.0.50727.4016, 3.0.30729.4037, 3.5.30729.01, 4.0.30319}  
    Z2T1DEFMVLA166  {2.0.50727.5420, 3.0.30729.5420, 3.5.30729.5420, 4.5.50938} 

.EXAMPLE
    C:\PS>  (Get-dotnetVersion z2t1defmvltx001).dotnetversion
    
    2.0.50727.5420
    3.0.30729.5420
    3.5.30729.5420
    4.5.50938

.LINK
    Credits
      http://www.happysysadm.com/2017/12/powershell-oneliner-to-list-all.html
      
.NOTES
    Version:        v1.0
    Author:         Bela Sajtos
    Contact:        bela.sajtos@gmail.com 
    PSversion:      3.0+
    Release Notes:  v1.0 (2017.12.16) - First working version of the function
                    v1.1 (2019.10.27) - include in module

#>
    [Cmdletbinding()]
    param (
        [Parameter()]
            [Alias('CN')]
            [String[]]
            $ComputerName = $env:COMPUTERNAME,

        [Parameter()]
            [ValidateNotNull()]
            [System.Management.Automation.PSCredential]
            [System.Management.Automation.Credential()]
            $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter()]
            [ValidateRange(1, 64)]
            [Int]
            $ThrottleLimit = 32
    )
    
    $Sessions = New-PSSession -Name 'DotNET' `
                              -ComputerName $ComputerName `
                              -ThrottleLimit $ThrottleLimit `
                              -Credential $Credential 
                              
                              
    $dotNetversions = Invoke-Command -AsJob -Session $Sessions -ScriptBlock {
        #5 paths can exist in registry specifying .net versions:
        $regex = 'v1.1.4322$|v2.0.50727$|v3.0$|v3.5$|v4\\Full$'

        try{
            $keys = (Get-Childitem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse -ErrorAction Stop |
                     Where-Object { $_.Name -match $regex } |
                     Select-Object -ExpandProperty Name)

            $temp = $keys | % { Get-Itemproperty "Registry::$($_)" } -ErrorAction Stop | Select-Object -ExpandProperty Version
        }
        catch {
            #return error message if registry entry not found.
            $temp = 'err'
        }
        
        #return of the invoke-command
        $out = New-Object PSObject -Property @{
               TargetMachine = $env:COMPUTERNAME
               DotNETVersion = $temp 
               }
        $out
    }
    
    #return of the function and remove the invoke-command encapsulation
    $dotNetversions =  Wait-Job $dotNetversions -Timeout 15 | Receive-Job
    $dotNetversions | select TargetMachine, DotNETversion

    Get-PSSession  | Remove-PSSession
 }