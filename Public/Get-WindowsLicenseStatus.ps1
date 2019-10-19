function Get-WindowsLicenseStatus {
<#
.SYNOPSIS
    Returns Windows License Status

.DESCRIPTION
    Returns Windows License Status

.PARAMETER ComputerName
	System.Array type parameter. It accepts array of target machines stored in variables/serverlist.txt files / or it accepts lists.
    Default value is $env:computername (localhost)

.EXAMPLE
    C:\PS> Get-WindowsLicenseStatus -ComputerName server1
    Description
    -----------
    These commands will search for updates 

.EXAMPLE
    -

.LINK
    https://docs.microsoft.com/en-us/previous-versions/windows/desktop/sppwmi/softwarelicensingproduct
      
.NOTES
    Version:        v1.0
    Author:         Bela Sajtos
    Contact:        bela.sajtos@gmail.com 
    PSversion:      3.0+
    Release Notes:  v1.0 (2017.12.16):
                    -First working version of the function


#>
    [Cmdletbinding()]
    param (
        [Parameter()]
            [Alias('CN')]
            [String[]]$ComputerName = $env:computername,

        [Parameter()]
            [ValidateNotNull()]
            [System.Management.Automation.PSCredential]
            [System.Management.Automation.Credential()]
            $Credential = [System.Management.Automation.PSCredential]::Empty
        
    )
    
    $Sessions = New-PSSession -Name 'GetWindowsLicense' `
                              -ComputerName $ComputerName `
                              -Credential $Credential `
                              -ErrorAction Stop
                              
    
    
   
                              
    $Result = Invoke-Command -AsJob -Session $Sessions -ScriptBlock {
        

        $InstalledLicense = Get-WmiObject -Query "Select * from SoftwareLicensingProduct Where `
            PartialProductKey IS NOT NULL AND ApplicationID = '55c92734-d682-4d71-983e-d6ec3f16059f'"
        
        Switch ($InstalledLicense.LicenseStatus)
        {
            0 {$lic = "Unlicensed"}
            1 {$lic = "Licensed"}
            2 {$lic = "Out-of-Box Grace Period"}
            3 {$lic = "Out-of-Tolerance Grace Period"}
            4 {$lic = "Non-Genuine Grace Period"}
            5 {$lic = "Notification"}
            6 {$lic = "ExtendedGrace"}
        }

        $out = New-Object PSObject -Property @{
               MachineName = $env:COMPUTERNAME
               WinLicense  = $lic
               KMS         = $InstalledLicense.KeyManagementServiceMachine
               Type        = ($InstalledLicense.Description).Substring($InstalledLicense.Description.IndexOf(',')+2)

               }
        $out
    }
    while (Get-Job -State 'Running') {sleep -Milliseconds 250}
    $Result = Get-Job $Result.Id | Receive-Job
    
    $result | select machinename, WinLicense, kms, type

    Get-Job | Remove-Job
    Get-PSSession  | Remove-PSSession
}

