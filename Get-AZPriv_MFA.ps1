<#

 Author: Github.com/Securethelogs
 This script is to find privileged role accounts that don't have MFA. If you do find them, do review and consider restricting them based on Network IP. 

#>

Write-Output ""
Write-Host "[*] Checking if module is installed" -ForegroundColor Yellow

if (Get-InstalledModule MSOnline){

 Write-Host "[*] MsOnline module is installed" -ForegroundColor Green
 Write-Host "[*] Please login" -ForegroundColor Yellow


 Connect-MsolService

 Write-Host "[*] Collecting admin roles, users and MFA status" -ForegroundColor Yellow
 Write-Output ""

 $roles = @(Get-MsolRole | Where-Object{$_.Name -like "*admin*"})

  foreach ($r in $roles){

    Write-Host "Role: $($r.Name)"
    $usrs = @(Get-MsolRoleMember -RoleObjectId $r.ObjectId)

        foreach ($u in $usrs){

            if ($u.EmailAddress -ne $null){

             $dets = New-Object PSObject
             $dets | Add-Member -MemberType NoteProperty -Name 'DisplayName' -Value $u.DisplayName
             $dets | Add-Member -MemberType NoteProperty -Name 'UPN' -Value $u.EmailAddress

                if (@((Get-MsolUser -UserPrincipalName $u.EmailAddress).StrongAuthenticationMethods.IsDefault) -contains "True"){
                
                    $dets | Add-Member -MemberType NoteProperty -Name 'MFA_Enabled' -Value "True"
                
                } else {

                    $dets | Add-Member -MemberType NoteProperty -Name 'MFA_Enabled' -Value "False"

                }


                $dets

            }

        }

        
   Write-Output ""

  }


} else {

    Write-Host "You need to install the MSOnline Module" -ForegroundColor Red

}