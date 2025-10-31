Import-Module AzureADPreview

try { 
    $var = Get-AzureADTenantDetail 
} 
catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] { 
    Write-Host "You're not connected to AzureAD"; 
    Write-Host "Make sure you have AzureAD mudule available on this system then use Connect-AzureAD to establish connection"; 
    $Credential = Get-Credential
    Connect-AzureAD -Credential $Credential
}


$targetedGroups = @()
$storeInfo = @{}
#$x = 0
$reportHash = @{}
$out = @()
$adds = ""
$DateTime = Get-Date -f "yyyy-MM-dd HH-mm"
<#
#region Authentication
$ClientID              = $API_Keys.UserName
$ClientSecret          = $API_Keys.GetNetworkCredential().Password
$TenantDomain          = 'fe7b0418-5142-4fcf-9440-7a0163adca0d'
$LoginURL              = 'https://login.microsoft.com'
$Resource              = 'https://graph.microsoft.com'
$TokenRequestBody      = @{grant_type="client_credentials";resource=$Resource;client_id=$ClientID;client_secret=$ClientSecret}
$oAuth                 = Invoke-RestMethod -Method Post -Uri $LoginURL/$TenantDomain/oauth2/token?api-version=1.0 -Body $TokenRequestBody
$AzureHeaders          = @{'Authorization'="$($oAuth.token_type) $($oAuth.access_token)"}
#endregion Authentication
#>

# Exclude specific locations from any update
$excludedLocations = @("9501")

$targetedGroups = (Get-ADGroup -filter { DisplayName -like "*_FrontEnd" } -SearchBase "OU=O365,OU=Exchange,DC=corp,DC=gianteagle,DC=com") 
$DynamicGroupSet = foreach ($group in $targetedGroups) { Get-AzureADMSGroup -Id $group.Name.Split("_")[1] }
$DynamicGroupSet | Export-Csv -Path C:\Temp\DynamicGroupSet_$DateTime.csv -Force -NoTypeInformation
foreach ($group in $DynamicGroupSet) {
    $store = $group.DisplayName.Split("_")[0]
    if (-not ($excludedLocations -contains $store)) {
        $storeInfo.add($store, $group.Id)
    }
}
foreach ($store in $storeinfo.Keys) {
    $allAdditions = @()
    $ExplicitAdditions = @()
    #$Filters = $DynamicGroupSet[$x].MembershipRule.Split('"') | Where-Object { $_ -match '^\d+$' -or $_ -match '^\w+([.]\w+)?@(corp[.])?gianteagle.com$' }
    $Filters = ($DynamicGroupSet | Where-Object { $_.displayName -match "^$store" }).MembershipRule.Split('"') | Where-Object { $_ -match '^\d+$' -or $_ -match '^\w+([.]\w+)?@(corp[.])?gianteagle.com$' }
    $Filters | ForEach-Object {
        if ($_ -match '^\d+$') {
        }
        else {
            $ExplicitAdditions += $_ 
        }
    }
    foreach ($ExplicitAddition in $ExplicitAdditions) {
        $allAdditions += " -or (user.userPrincipalName -eq " + '"' + $ExplicitAddition + '"' + ")"
    }
   
    $reportHash.Add($store, $allAdditions)
    #$x++
}
$reportedStores = $reportHash.Keys
$reportedAdds = $reportHash.Values
$reportHash | Out-File -FilePath C:\Temp\reportHash_$DateTime.txt -Force 
$reportedStores[0] | Out-File -FilePath C:\Temp\reportStores_$DateTime.txt -Force 
$reportedAdds[0] | Out-File -FilePath C:\Temp\reportAdds_$DateTime.txt

$reportHash.Keys | foreach-object {
    $adds += " " + $reportHash["$_"]
    $filterRule = '(user.Department -contains ' + '"' + $_ + '") ' + '-and (user.extensionAttribute3 -eq "A") -and ((user.extensionAttribute13 -In ["10010","80003","80014","80066","10136","10159","10181","10183","10185","70128","80173","80177","80191","80174"]) -or (user.extensionAttribute6 -contains "10010" -and user.extensionAttribute6 -notContains "ER10010") -or (user.extensionAttribute6 -contains "80003" -and user.extensionAttribute6 -notContains "ER80003") -or (user.extensionAttribute6 -contains "80014" -and user.extensionAttribute6 -notContains "ER80014") -or (user.extensionAttribute6 -contains "80066" -and user.extensionAttribute6 -notContains "ER80066") -or (user.extensionAttribute6 -contains "10136" -and user.extensionAttribute6 -notContains "ER10136") -or (user.extensionAttribute6 -contains "10159" -and user.extensionAttribute6 -notContains "ER10159") -or (user.extensionAttribute6 -contains "10181" -and user.extensionAttribute6 -notContains "ER10181") -or (user.extensionAttribute6 -contains "10183" -and user.extensionAttribute6 -notContains "ER10183") -or (user.extensionAttribute6 -contains "10185" -and user.extensionAttribute6 -notContains "ER10185") -or (user.extensionAttribute6 -contains "70128" -and user.extensionAttribute6 -notContains "ER70128") -or (user.extensionAttribute6 -contains "80173" -and user.extensionAttribute6 -notContains "ER80173") -or (user.extensionAttribute6 -contains "80177" -and user.extensionAttribute6 -notContains "ER80177") -or (user.extensionAttribute6 -contains "80191" -and user.extensionAttribute6 -notContains "ER80191") -or (user.extensionAttribute6 -contains "80174" -and user.extensionAttribute6 -notContains "ER80174"))' 
    #(user.Department -contains "3395") -and (user.extensionAttribute3 -eq "A") -and ((user.extensionAttribute13 -In ["10041","10046","10060","10061","10062","10080","10084","10085","10086","10087","10105","10140","10141","10143","10144","10145","10168","10169","10174","10176","10177","10178","21083","80047","80123","80207","80215","80225","10182","80232"]) -or (user.extensionAttribute6 -contains "10041") -or (user.extensionAttribute6 -contains "10046") -or (user.extensionAttribute6 -contains "10060") -or (user.extensionAttribute6 -contains "10061") -or (user.extensionAttribute6 -contains "10062") -or (user.extensionAttribute6 -contains "10080") -or (user.extensionAttribute6 -contains "10084") -or (user.extensionAttribute6 -contains "10085") -or (user.extensionAttribute6 -contains "10086") -or (user.extensionAttribute6 -contains "10087") -or (user.extensionAttribute6 -contains "10105") -or (user.extensionAttribute6 -contains "10140") -or (user.extensionAttribute6 -contains "10141") -or (user.extensionAttribute6 -contains "10143") -or (user.extensionAttribute6 -contains "10144") -or (user.extensionAttribute6 -contains "10145") -or (user.extensionAttribute6 -contains "10168") -or (user.extensionAttribute6 -contains "10169") -or (user.extensionAttribute6 -contains "10174") -or (user.extensionAttribute6 -contains "10176") -or (user.extensionAttribute6 -contains "10177") -or (user.extensionAttribute6 -contains "10178") -or (user.extensionAttribute6 -contains "21083") -or (user.extensionAttribute6 -contains "80047") -or (user.extensionAttribute6 -contains "80123") -or (user.extensionAttribute6 -contains "80207") -or (user.extensionAttribute6 -contains "80215") -or (user.extensionAttribute6 -contains "80225"))
    $out += $filterRule + $adds
    $out | Out-File -FilePath C:\Temp\whatIsSet_$DateTime.txt 
    $filterRule = $filterRule + $adds
    try {
        Set-AzureADMSGroup -Id $storeinfo["$_"] -MembershipRule $filterRule -MembershipRuleProcessingState "On"
        $post = Get-AzureADMSGroup -Id $storeinfo["$_"]
        ("STORE=$_`nID=" + $storeinfo["$_"] + "`nNEW=" + $filterRule + "`nPOSTSET=" + $post.MembershipRule + "`n") | Out-File -FilePath C:\Temp\whatIsSet_$DateTime.txt -Append
    }
    catch {
        Write-Error "Failed to update MembershipRule for store $_ (" + $storeinfo["$_"] + "): " + $_
    }

    <#
    [uri]$SignInsUrl = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=userPrincipalName eq '$_'"
    $SignIns = Invoke-RestMethod -Uri $SignInsUrl.AbsoluteUri -Headers $AzureHeaders

    PATCH https://graph.microsoft.com/beta/groups
    {
        "groupTypes": [
            "Unified",
            "DynamicMembership"
        ],
        "membershipRule": "user.department -eq \"Marketing\"",
        "membershipRuleProcessingState": "on"
    }
#>
    $adds = $null
}
