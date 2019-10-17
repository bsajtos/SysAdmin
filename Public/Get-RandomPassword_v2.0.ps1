function Get-RandomPassword {
    param (
        [ValidateRange(8,32)]
        [Int]
        $Length = 8

    )
    Add-Type -AssemblyName System.web
    [System.Web.Security.Membership]::GeneratePassword($Length,1)

}