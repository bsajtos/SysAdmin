
[version]$ver = '1.0'

#Get public and private functions
$PublicFunctions = @( Get-ChildItem -Path "$(Split-Path $PSScriptRoot -Parent)\Public\*.ps1" -ErrorAction SilentlyContinue )
$PrivateFunctions = @( Get-ChildItem -Path "$(Split-Path $PSScriptRoot -Parent)\Private\*.ps1" -ErrorAction SilentlyContinue )


#Dot sourcing the functions
foreach ($scriptfile in @($PublicFunctions + $PrivateFunctions)){
    try   {
        . $scriptfile.fullname
        Write-Verbose "$($scriptfile.Name) imported successfully."
    }
    catch {Write-Error "Failed to import function $($scriptfile.fullname)"}

}


#Variables with module scope



#Making the public functions available for the users
Export-ModuleMember -Function $PublicFunctions.basename

