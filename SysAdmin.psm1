

#Get public and private functions
$PublicFunctions = @( Get-ChildItem -Path "$($PSScriptRoot)\Public\*.ps1" -ErrorAction SilentlyContinue )
$PrivateFunctions = @( Get-ChildItem -Path "$($PSScriptRoot)\Private\*.ps1" -ErrorAction SilentlyContinue )

$AllFunction = $($PublicFunctions + $PrivateFunctions)


#Dot sourcing the functions
foreach ($func in $AllFunction){
    try   {
        . $func.fullname
    }
    catch {Write-Error "Failed to import function $($func.fullname)"}

}


#Variables with module scope




#Exporting the public functions
$PublicFunctions | % {Export-ModuleMember -Function $_.basename}



