# Author: XStag0 
# Connect methods: https://docs.microsoft.com/en-us/powershell/module/azuread/connect-azuread?view=azureadps-2.0

$AZcerts = @()
$AZexpiring = @()

# This can change, dependent on the frequency of monitoring.
$future30 = (Get-Date).AddDays(30)

<#
More Filtering Options based on: {($_.Tags -contains "WindowsAzureActiveDirectoryGalleryApplicationNonPrimaryV1")}

    - OAuth apps would have a tag called "WindowsAzureActiveDirectoryIntegratedApp"
    - Gallery SAML Apps would have a tag called "WindowsAzureActiveDirectoryGalleryApplicationPrimaryV1"
    - Non-Gallery SAML Apps would have a tag called "WindowsAzureActiveDirectoryCustomSingleSignOnApplication"

#>

foreach ($azsp in ((Get-AzureADServicePrincipal -All $true).ObjectId)){

    $app = Get-AzureADServicePrincipal -ObjectId $azsp

    
    $az = New-Object PSObject
    $az | Add-Member -MemberType NoteProperty -Name 'DisplayName' -Value $app.DisplayName
    $az | Add-Member -MemberType NoteProperty -Name 'AppDisplayName' -Value $app.AppDisplayName
    $az | Add-Member -MemberType NoteProperty -Name 'ObjectId' -Value $app.ObjectId
    $az | Add-Member -MemberType NoteProperty -Name 'Enabled' -Value $app.AccountEnabled
    

    $certn = 1
    $expchk = "N"

    foreach ($keycrt in $app.KeyCredentials){

        $az | Add-Member -MemberType NoteProperty -Name "Cert$($certn)Id" -Value $keycrt.KeyId
        $az | Add-Member -MemberType NoteProperty -Name "Cert$($certn)_EndDate" -Value $keycrt.EndDate

        if ($keycrt.EndDate -lt $future30){

            $az | Add-Member -MemberType NoteProperty -Name "Cert$($certn)_Expiring" -Value "YES"
            $expchk = "Y"
            
        } else { $az | Add-Member -MemberType NoteProperty -Name "Cert$($certn)_Expiring" -Value "NO" }


        $certn++

    }

        if ($expchk -eq "Y"){

            $AZexpiring += $az

        }

        $AZcerts += $az
    

}

# Custom this to how you want | If feeding into an API, | ConvertTo-Json is good, else | Out-CSV / Export-CSV C:\...

Write-Host "Expring within the next $($future30) days!:"
$AZexpiring | Format-Table

Write-Output ""

$vall = Read-Host -Prompt "View all?"

if ($vall -eq "Y"){

    Write-Host "All My Apps:"
    $AZcerts | Format-Table     


}
