$PublicFunctions = @( Get-ChildItem -Path "$(Split-Path $PSScriptRoot -Parent)\Public\*.ps1" -ErrorAction SilentlyContinue )
$PrivateFunctions = @( Get-ChildItem -Path "$(Split-Path $PSScriptRoot -Parent)\Private\*.ps1" -ErrorAction SilentlyContinue )

$PublicFunctions
$PrivateFunctions
