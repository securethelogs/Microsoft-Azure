
# Author: @XstagO
# Remember to add your auth method prior to $GetNICs 

# --- Add your Auth Method ---



# --- Add your Auth Method ---



$GetNICs = @(Get-AzNetworkInterface)
$PiPDets = @()

foreach ($i in $GetNICs){

# Create Temp Object
$rsc = New-Object PSCustomObject
$rsc | Add-Member -MemberType NoteProperty -Name "Date" -Value (Get-Date -Format dd-MM-yyyy)

# Resource Details
$rsc | Add-Member -MemberType NoteProperty -Name "ResourceName" -Value (Get-AzResource -ResourceId ($i.VirtualMachine.Id)).Name
$rsc | Add-Member -MemberType NoteProperty -Name "ResourceLocation" -Value (Get-AzResource -ResourceId ($i.VirtualMachine.Id)).Location
$rsc | Add-Member -MemberType NoteProperty -Name "ResourceGroupName" -Value (Get-AzResource -ResourceId ($i.VirtualMachine.Id)).ResourceGroupName

# Network Security Group
$rsc | Add-Member -MemberType NoteProperty -Name "NSGName" -Value (Get-AzResource -ResourceId ($i.NetworkSecurityGroup.Id)).Name


# Public IP Details
if ($i.IpConfigurations.PublicIpAddress.Id){

    $PiP = Get-AzPublicIpAddress -Name (Get-AzResource -ResourceId ($i.IpConfigurations.PublicIpAddress.Id)).Name -ResourceGroupName (Get-AzResource -ResourceId $i.IpConfigurations.PublicIpAddress.Id).ResourceGroupName

    $rsc | Add-Member -MemberType NoteProperty -Name "PiPName" -Value $PiP.Name
    $rsc | Add-Member -MemberType NoteProperty -Name "PiP" -Value $PiP.IpAddress
    $rsc | Add-Member -MemberType NoteProperty -Name "PiPMethod" -Value $PiP.PublicIpAllocationMethod

    $PiPDets += $rsc

}

}

# Output to JSON
$PiPDets | ConvertTo-Json
