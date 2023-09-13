#---------------------------------------------------------------------------------------------------------
#	<copyright file="BaseCommon.psm1" company="Microsoft" application="Azure DevOps Bootstrap Slim">
#	Copyright  © Microsoft Corporation.  All rights reserved.
#	</copyright>
#------------------------------------------------------------------------------------------------------------

Function CheckPrereqs {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] 
        $resourceGroupName,
        [Parameter(Mandatory = $true)]
        [bool] 
        $useSelfSignedCertificate,
        [Parameter(Mandatory = $true)]
        [string] 
        $localCertificatePolicyPath,
        [Parameter(Mandatory = $true)]
        [bool] 
        $useImportedCertificate,
        [Parameter(Mandatory = $false)]
        [securestring] 
        $importedCertificatePassword,
        [Parameter(Mandatory = $false)]
        [string] 
        $importedCertificateFilePath,
        [Parameter(Mandatory = $true)]
        [string] 
        $jumpBoxName,
        [Parameter(Mandatory = $true)]
        [string] 
        $appName,
        [Parameter(Mandatory = $true)]
        [string] 
        $instanceNumber,
        [Parameter(Mandatory = $true)]
        [string] 
        $location
    )

    # VERIFY BOOTSTRAP PREREQUISITES
    Write-Host "`tChecking bootstrap prerequisites..."
    try {
        Get-BootstrapPrerequisites -bootstrapPrerequisitesFile .\bootstrapPrereqs.json -ErrorAction Stop
    } catch {
        Write-Host "`t`t$($_.Exception.Message)" -ForegroundColor Red
        return 1
    }
    
    # CHECK CERTIFICATE PREREQUISITES - SELF SIGNED
    if ($useSelfSignedCertificate) {
        Write-Host "`tChecking self-signed certificate prerequisites..."
        if (-not (Test-Path -Path $($localCertificatePolicyPath))) {
            Write-Host "The certificate policy file cannot be located. Please ensure the policy file is published at $($localCertificatePolicyPath)" -ForegroundColor Red
            return 1
        } else {
            Write-Host "`t`tThe certificate policy file is available at $($localCertificatePolicyPath)"
        }
    }

    # CHECK CERTIFICATE PREREQUISITES - IMPORTED
    if ($useImportedCertificate) {
        Write-Host "`tChecking imported certificate prerequisites..."
        if (-not (Test-Path -Path $importedCertificateFilePath)) {
            Write-Host "The certificate file cannot be located. Please ensure the file is available at $($importedCertificateFilePath)" -ForegroundColor Red
            return 1
        } else {
            Write-Host "`t`tThe certificate file is available at $($importedCertificateFilePath)"
        }
        if ($importedCertificatePassword.Length -eq 0) {
            try {
                $certificate = Get-PfxCertificate -FilePath $importedCertificateFilePath -NoPromptForPassword -ErrorAction Stop
            } catch {
                Write-Host "There was an error reading the certificate file: $($PSItem.Exception.Message)" -ForegroundColor Red
                return 1
            }
        } else {
            try {
                $certificate = Get-PfxCertificate -FilePath $importedCertificateFilePath -Password $importedCertificatePassword -ErrorAction Stop
            } catch {
                Write-Host "There was an error reading the certificate file: $($PSItem.Exception.Message)" -ForegroundColor Red
                return 1
            }
        }

        # Check certificate properties
        if (-not ($certificate.HasPrivateKey)) {
            Write-Host "Provided certificate doesn't have a private key, so it can't be used" -ForegroundColor Red
            return 1
        }
        if ($certificate.NotBefore -gt (Get-Date)) {
            Write-Host "Certificate not yet valid. Will be valid at $($certificate.NotBefore)" -ForegroundColor Red
            return 1
        }
        if ($certificate.NotAfter -lt (Get-Date)) {
            Write-Host "Certificate already expired. Expiration date is $($certificate.NotAfter)" -ForegroundColor Red
            return 1
        }
        Write-Host "`t`tCertificate to be imported has a private key and isn't expired"
    }

    # CHECK JUMPBOX VIRTUAL MACHINE NAMING
    Write-Host "`tChecking Jumpbox Virtual Machine prerequisites..."
    if (-not (IsValidVmName -Name $jumpBoxName -OS "Windows")) {
        Write-Host "`t`tThe Jumpbox Virtual Machine name, '$($jumpBoxName)' is not valid." -ForegroundColor Red
        return 1
    } else {
        Write-Host "`t`tThe Jumpbox Virtual Machine name, '$($jumpBoxName)' is valid."
    }

    # CHECK ADO VMSCALESET NAMING
    Write-Host "`tChecking Azure DevOps Virtual Machine Scale Set prerequisites..."
    if (-not (IsValidVmName -Name "ado-$($appName)-$($instanceNumber)" -OS "Linux")) {
        Write-Host "The Azure DevOps VMScaleSet name is not valid."
        Write-Host "`t`tThe Azure DevOps Virtual Machine Scale Set name, 'ado-$($appName)-$($instanceNumber)' is not valid." -ForegroundColor Red
        return 1
    } else {
        Write-Host "`t`tThe Azure DevOps Virtual Machine Scale Set name, 'ado-$($appName)-$($instanceNumber)' is valid."
    }

    return 0
}

Function CheckPrereqsRequireAuth {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] 
        $keyVaultName,
        [Parameter(Mandatory = $true)]
        [string] 
        $ApiManagementServiceName,
        [Parameter(Mandatory = $true)]
        [string] 
        $resourceGroupName,
        [Parameter(Mandatory = $true)]
        [string] 
        $azureEnvironment,
        [Parameter(Mandatory = $true)]
        [string] 
        $appName,
        [Parameter(Mandatory = $true)]
        [string] 
        $instanceNumber,
        [Parameter(Mandatory = $true)]
        [string] 
        $location,
        [Parameter(Mandatory = $true)]
        [string] 
        $AzureDevOpsPAT,
        [Parameter(Mandatory = $true)]
        [string] 
        $OrganizationName,
        [Parameter(Mandatory = $true)]
        [string] 
        $ProjectName,
        [Parameter(Mandatory = $true)]
        [string] 
        $aksVersion
    )
    
    # VERIFY AZURE REGION
    Write-Host "`tChecking the provided Azure region."
    $regions = Get-AzLocation
    $regionMatch = $false
    foreach ($r in $regions){
        if ($r.Location -eq $location){
            $regionMatch = $true
            break
        }
    }
    if ($regionMatch -eq $false){
        Write-Host "`t'tThe specified Azure region is not valid."
        return 1
    }

    #region CHECK KEYVAULT
    #
    Write-Host "`tChecking Key Vault prerequisites..."
    if ($keyVaultName.Length -gt 23) {
        Write-Host "Please verify name of KeyVault is less than 23 characters" -ForegroundColor Red
        return 1
    } else {
        Write-Host "`t`tKey Vault name '$keyVaultName' is compliant with Azure naming conventions"
    }

    $kv = Get-AzKeyVault -VaultName $keyVaultName -ResourceGroupName $resourceGroupName -ErrorAction SilentlyContinue
    
    if ($null -eq $kv) {
        # Check name availability for key vault
        try {
            $body = '"name": "{0}", "type": "{1}"' -f $keyVaultName, 'Microsoft.KeyVault/vaults'
            $authorizationToken = Get-AccesTokenFromCurrentUser
            $uri = "https://management.azure.com/subscriptions/" + "$((Get-AzContext).Subscription.Id)" + "/providers/Microsoft.KeyVault/checkNameAvailability?api-version=2019-09-01"

            $response = Invoke-WebRequest -Method POST -body "{$body}" -Uri $uri -Headers @{Authorization = $AuthorizationToken } -ContentType "application/json"
            $responseOutput = $response | ConvertFrom-Json |
                Select-Object @{N = 'Name'; E = { $keyVaultName } }, @{N = 'Type'; E = { KeyVault } }, @{N = 'Available'; E = { $_ | Select-Object -ExpandProperty *available } }, Reason, Message
        } catch {
            Write-Host $Error[0].Exception
            return 1
        }
        # If key vault name is available proceed, if not exit
        if (-not ($responseOutput.Available -eq "True")) {
            Write-Host "`t`tThe name '$keyVaultName' is not available in '$azureEnvironment'. Please verify that the name is valid, unique, or purge deleted key vaults" -ForegroundColor Red
            return 1
        } else {
            Write-Host "`t`tThe name '$keyVaultName' is available in '$azureEnvironment' and will be use to deploy the Key Vault"
        }
    }
    #endregion CHECK KEYVAULT


    #region CHECK ApiManagementServiceName
    #
    Write-Host "`tChecking APIManagement prerequisites..."
    if ($ApiManagementServiceName.Length -gt 50) {
        Write-Host "Please verify name of APIManagement is less than 50 characters" -ForegroundColor Red
        return 1
    } else {
        Write-Host "`t`tKey Vault name '$ApiManagementServiceName' is compliant with Azure naming conventions"
    }

    $apims = Get-AzAPIManagement -Name $ApiManagementServiceName -ResourceGroupName $resourceGroupName -ErrorAction SilentlyContinue
    
    if ($null -eq $apims) {
        # Check name availability for API Management Service
        try {
            $body = '"name": "{0}"' -f $ApiManagementServiceName
            $authorizationToken = Get-AccesTokenFromCurrentUser
            $uri = "https://management.azure.com/subscriptions/" + "$((Get-AzContext).Subscription.Id)" + "/providers/Microsoft.APIManagement/checkNameAvailability?api-version=2021-08-01"

            $response = Invoke-RestMethod -Method POST -body "{$body}" -Uri $uri -Headers @{Authorization = $AuthorizationToken } -ContentType "application/json"
        } catch {
            Write-Host $Error[0].Exception
            return 1
        }
        # If key vault name is available proceed, if not exit
        if (-not ($response.nameAvailable -eq "True")) {
            Write-Host "`t`tThe name '$ApiManagementServiceName' is not available in '$azureEnvironment'. Please verify that the name is valid and unique" -ForegroundColor Red
            return 1
        } else {
            Write-Host "`t`tThe name '$ApiManagementServiceName' is available in '$azureEnvironment' and will be use to deploy the API Management Service"
        }
    }
    #endregion CHECK ApiManagementServiceName

    # CHECK AKS VERSION AVAILABILITY
    #
    Write-Host "`tChecking if AKS version $($aksVersion) is available in $($Location) ..."
    $availableAksVersion = Get-AzAksVersion -Location $Location
    if ($availableAksVersion.OrchestratorVersion -contains $aksVersion) {
        Write-Host "`t`tAKS version $($aksVersion) is available in $($Location)."
    } else {
        Write-Host "`t`tAKS version $($aksVersion) not available in $($Location)." -ForegroundColor Red
        Write-Host "`t`tAvailable versions are:" $($availableAksVersion.OrchestratorVersion -join ", ") -ForegroundColor Red
        Write-Host "`t`tPlease update the 'AksVersion' variable in '$($VariablesFile)'." -ForegroundColor Red
        return 1
    }

    # CHECK USERS ADO MEMBSHIP
    # 
    # Write-Host "`tChecking if user is a member of [$($ProjectName)]\Project Administrators ..."
    # $AuthenticatedUser = ($(Get-AzContext).Account.Id)
    # $GetUserIsAdoAdminParameters = @{
    #     PAT                  = $azureDevOpsPAT
    #     OrgName              = $organizationName
    #     ProjectName          = $projectName
    #     AzureUserId          = $AuthenticatedUser
    # }

    # $result = Get-UserIsAdoAdmin @GetUserIsAdoAdminParameters
    # if(!$result) {
    #     Write-Host "`t`tAuthenticated User $($AuthenticatedUser)" `
    #         + "is not is a member of [$($ProjectName)]\Project Administrators." `
    #     return 1
    # }

    return 0
}

function Get-BootstrapPrerequisites {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] 
        $bootstrapPrerequisitesFile
    )

    begin {
        try {
            $null = Test-Path -Path $bootstrapPrerequisitesFile -ErrorAction Stop
        } catch {
            Write-Error -Message "The bootstrap prerequisites file cannot be located. Please ensure the file is published at $bootstrapPrerequisitesFile"
            return 1
        }
        $bootstrapReqs = Get-Content $bootstrapPrerequisitesFile -Raw | ConvertFrom-Json
    }
    process {
        foreach ($bootstrapReq in $bootstrapReqs) {
            # Get the installed version for each type of prerequisites
            switch ($bootstrapReq.type) {
                "PowerShell" {
                    try {
                        [System.Management.Automation.SemanticVersion]$installedVersion = $PSVersionTable.PSVersion
                    }
                    catch {
                        Write-Error -Message "The PowerShell version $($PSVersionTable.PSVersion) is not supported. Please upgrade to version '$($bootstrapReq.version)' and try again"
                        return 1
                    }
                    break
                }
                "PowerShellModule" {
                    try {
                        [System.Management.Automation.SemanticVersion]$installedVersion = (Get-InstalledModule $bootstrapReq.name -ErrorAction Stop).Version
                    } catch {
                        Write-Error -Message "The PowerShell module '$($bootstrapReq.name)' is not installed. Please install the module and try again"
                        return 1
                    }
                    break
                }
                "AzCli" {
                    try { 
                        [System.Management.Automation.SemanticVersion]$installedVersion = ((az version | convertFrom-Json).'azure-cli')
                    } catch {
                        Write-Error -Message "The Azure Command-Line Interface (az cli) is not installed. Please install the Azure Command-Line Interface and try again. https://docs.microsoft.com/en-us/cli/azure/"
                        return 1
                    }
                    break
                }
                "AzCliExtension" {
                    [System.Management.Automation.SemanticVersion]$installedVersion = (az extension list -o json --query "[?name=='$($bootstrapReq.name)']" | ConvertFrom-Json).version
                    if ($null -eq $installedVersion) {
                        Write-Error -Message "The Azure CLI extension '$($bootstrapReq.name)' is not installed. Please install the extension and try again"
                        return 1
                    }
                    break
                }
                default {
                    Write-Error -Message "Unknown type $type"
                    return 1
                    break
                }
            }
            [System.Management.Automation.SemanticVersion]$requiredVersion = $bootstrapReq.version
            
            # Compare the installed version with the required version
            # The SemanticVersion object CompareTo method returns:
            #  - "1" if the version is greater to the one compared
            #  - "0" if the version is equal to the one compared
            #  - "-1" if the version is lower to the one compared
            switch ($bootstrapReq.versionReq) {
                ">=" {
                    if ($installedVersion.CompareTo($requiredVersion) -eq -1) {
                        Write-Error -Message "$($bootstrapReq.name) version $requiredVersion is required, but $($bootstrapReq.name) version $installedVersion is installed"
                        return 1
                    } else {
                        Write-Host "`t`t$($bootstrapReq.name) version $installedVersion is installed"
                    }
                    break
                }
                "==" {
                    if ($installedVersion.CompareTo($requiredVersion) -ne 0) {
                        Write-Error -Message "$($bootstrapReq.name) version $requiredVersion is required, but $($bootstrapReq.name) version $installedVersion is installed"
                        return 1
                    } else {
                        Write-Host "`t`t$($bootstrapReq.name) version $installedVersion is installed"
                    }
                    break
                }
                "=<" {
                    if ($installedVersion.CompareTo($requiredVersion) -eq 1) {
                        Write-Error -Message "$($bootstrapReq.name) version $requiredVersion is required, but $($bootstrapReq.name) version $installedVersion is installed"
                        return 1
                    } else {
                        Write-Host "`t`t$($bootstrapReq.name) version $installedVersion is installed"
                    }
                    break
                }
                default {
                    Write-Error -Message "Unknown version requirement $($bootstrapReq.versionReq)"
                    return 1
                    break
                }
            }
        }
    }
    end {
    }
}

function ConvertTo-PemFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("PFX")]
        [string] 
        $sourceFormat,
        [Parameter(Mandatory = $true)]
        [string] 
        $pfxFilePath,
        [Parameter(Mandatory = $false)]
        [securestring]
        $pfxFilePassword
    )

    begin {
        if ($pfxFilePassword) {
            $clearTextPassword = ConvertFrom-SecureString -SecureString $pfxFilePassword -AsPlainText
        } else {
            $clearTextPassword = $null
        }
    }
    process {
        switch ($sourceFormat) {
            "PFX" {
                Write-Host "`t`t`t`tGetting PEM from PFX file"
                ..\tools\openssl\openssl.exe pkcs12 -in $pfxFilePath -nodes -passin pass:$clearTextPassword  -out .\tmpcert.pem
                if ($? -eq $false) {
                    Remove-Item -Path .\tmpcert.pem -Force -Confirm:$false -ErrorAction SilentlyContinue
                    throw "Failed to get PEM from PFX file"
                }
                Write-Host "`t`t`t`tCreating a clutter free PEM file"
                ..\tools\openssl\openssl.exe pkcs8 -topk8 -nocrypt -in .\tmpcert.pem | Out-File -FilePath .\cert.pem -Encoding utf8 -Force -Confirm:$false
                if ($? -eq $false) {
                    Remove-Item -Path .\tmpcert.pem -Force -Confirm:$false -ErrorAction SilentlyContinue
                    throw "Failed to get private key from temp PEM file"
                }
                ..\tools\openssl\openssl.exe x509 -in .\tmpcert.pem | Out-File -FilePath .\cert.pem -Append -Encoding utf8 -Force -Confirm:$false
                if ($? -eq $false) {
                    Remove-Item -Path .\tmpcert.pem -Force -Confirm:$false -ErrorAction SilentlyContinue
                    throw "Failed to get public key from temp PEM file"
                }
                Write-Output (Get-ChildItem -path .\cert.pem)
            }
        }
    }
    end {
        Write-host "`t`t`t`tRemoving temp PEM file"
        Remove-Item -Path .\tmpcert.pem -Force -Confirm:$false -ErrorAction SilentlyContinue
    }
}

Function Authenticate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] 
        $subscriptionId,
        [Parameter(Mandatory = $true)]
        [string] 
        $tenantId
    )
    #Connect to Azure
    try {
        if ($IsWindows) {
            Write-Host "`tUse the tab opened in the default browser to authenticate to Azure"
            $context = Connect-AzAccount -Tenant $tenantId -ErrorAction 'Stop' -WarningAction SilentlyContinue
        } else {
            $context = Connect-AzAccount -Tenant $tenantId -UseDeviceAuthentication -ErrorAction 'Stop' -WarningAction SilentlyContinue
        }
        Write-Host "`tSetting Azure context to subscription $($subscriptionId)"
        $context = Set-AzContext -SubscriptionId $subscriptionId -WarningAction SilentlyContinue
    } catch {
        Write-Error -Message $_.Exception
        return 1
    }
}

Function Connect-AzServicePrincipal {
    param (
        [Parameter(Mandatory = $true)]
        [string] 
        $subscriptionId,
        [Parameter(Mandatory = $true)]
        [string] 
        $tenantId,
        [Parameter(Mandatory = $true)]
        [string]
        $ServicePrincipalAppId,
        [Parameter(Mandatory = $false)]
        [String]
        $ClientSecret,
        [Parameter(Mandatory = $false)]
        [string]
        $CertificateThumbprint,
        [Parameter(Mandatory = $false)]
        [string]
        $PemFilePath        
    )
    
    Write-Host "`tDisabling auto caching of credentials ..."
    $null = Disable-AzContextAutosave -Scope Process
    
    if($CertificateThumbprint) {
        Connect-AzAccount -ServicePrincipal -SubscriptionId $subscriptionId  -ApplicationId $ServicePrincipalAppId `
            -TenantId $tenantId -CertificateThumbprint $CertificateThumbprint -ErrorAction Stop

        if ($PemFilePath.Length -eq 0){
            Write-Host "CertBundle path must be specified for az login using certificates."
        }
        else{
            $result = (az login --service-principal --username $ServicePrincipalAppId --password $PemFilePath --tenant $tenantId)
        }
    }

    else {
        $secureSecret = ($ClientSecret | ConvertTo-SecureString -Force -AsPlainText)
        $AppCred = (New-Object System.Management.Automation.PSCredential $ServicePrincipalAppId, $secureSecret)
        Connect-AzAccount -ServicePrincipal -SubscriptionId $subscriptionId `
            -TenantId $tenantId -Credential $AppCred -ErrorAction Stop

        $result = (az login --service-principal --username $ServicePrincipalAppId --password $ClientSecret --tenant $tenantId)       
    }
}

Function Build-AzContextObject {
    param (
        [Parameter(Mandatory = $true)]
        $Context
    )
    return ($Context | ConvertTo-Json | ConvertFrom-Json)
}

Function Get-UserIsAdoAdmin {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] 
        $ProjectName,
        [Parameter(Mandatory = $true)]
        [string] 
        $PAT,
        [Parameter(Mandatory = $true)]
        [string] 
        $OrgName,
        [Parameter(Mandatory = $true)]
        [string] 
        $AzureUserId,
        [string]
        $ApiVersion = "6.1-preview.1"
    )

    $basicAuthPair = ":$($PAT)"
    $encodedToken = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($basicAuthPair))

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"

    $headers.Add("Authorization", "Basic $($encodedToken)")
    $getOrgnizationGroupsURL = "https://vssps.dev.azure.com/$($OrgName)/"+
        "_apis/graph/groups?api-version=$($ApiVersion)"

    try {
        $response = Invoke-WebRequest -Uri $getOrgnizationGroupsURL -Method 'GET' -Headers $headers
        $groups = ($response.Content | ConvertFrom-Json).value
    }  catch {
        Write-Error "Error Fetching Project Organizations"
        Write-Output "Check your Azure DevOps PAT for Read permissions on 'Project and Team'"
        exit 1
    }

    $groupId = $null

    foreach ($group in $groups) {
        if($group.principalName -eq "[$($ProjectName)]\Project Administrators") {
            $groupId = $group.originId     
            break
        }
    }

    $getGroupMembersURL = "https://vsaex.dev.azure.com/$($OrgName)/" + 
        "_apis/groupentitlements/$($groupId)/" +
        "members?$($ApiVersion)"
    
    try {
        $response = Invoke-WebRequest -Uri $getGroupMembersURL -Method 'GET' -Headers $headers
    } catch {
        Write-Output "Error Fetching Group Membership"
        exit 1
    }

    $members = ($response.Content | ConvertFrom-Json).members
    
    foreach($member in $members){
        if($member.user.principalName -eq $AzureUserId){
            return $true
            break
        }
    }

    return $false
}

Function Get-AccesTokenFromCurrentUser {
    $azContext = Get-AzContext
    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList $azProfile
    $token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)
    ('Bearer ' + $token.AccessToken)
}

Function Get-AzDevOpsPools ([string]$OrgUrl, [string]$OrgName, [string]$PAT, [string]$ApiVersion = "6.0") {

    $encodedPAT = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$($PAT)"))

    $poolsUrl = "https://dev.azure.com/$($OrgName)/_apis/distributedtask/pools?api-version=$($ApiVersion)"
    try {
        $pools = (Invoke-RestMethod -Uri $poolsUrl -Method 'Get' -Headers @{Authorization = "Basic $($encodedPAT)" }).value
    } catch {
        Write-Error "`tAcessing Agent Pools for $($OrgName) failed, ensure Azure DevOps PAT has Agent Pools: Read & Manage Permissions"
        exit 1
    }

    return $pools
}

Function Get-AzDevOpsPool  ([string]$OrgUrl, [string]$OrgName, [string]$PAT, [string]$PoolName) {

    $pools = Get-AzDevOpsPools -OrgUrl $OrgUrl -OrgName $OrgName -PAT $PAT

    foreach ($pool in $pools) {
        if ($pool.name -eq $PoolName) {
            return $pool
        }
    }

    return $null
}

Function Remove-AzDevOpsPool  ([string]$OrgUrl, [string]$OrgName, [string]$PAT, [PSCustomObject]$Pool, [string]$ApiVersion = "6.0" ) {

    $encodedPAT = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$($PAT)"))
    $uriOrga = "https://$($OrgUrl)/$($OrgName)"
    $url = "$($uriOrga)/_apis/distributedtask/pools/$($Pool.id)?api-version=$($ApiVersion)"
    try {
        $pools = (Invoke-RestMethod -Uri $url -Method 'DELETE' -Headers @{Authorization = "Basic $($encodedPAT)" }).value
    } catch {
        Write-Error "`tAcessing Agent Pools for $($OrgName) failed, ensure Azure DevOps PAT has Agent Pools: Read & Manage Permissions"
        exit 1
    }

    return $pools
}

Function Add-AzDevOpsPool  ([string]$PAT, [string]$OrgUrl, [string]$OrgName, [string]$PoolName, 
    [string]$ProjectGuid, [string]$ServiceConnectorName, [string]$SubscriptionId, [string]$rgName, 
    [string]$VMSSName, [int]$MaxCapacity = 4, [int]$IdleCapacity = 1 ) {
    
    $ApiVersion = "7.0"
    $basicAuthPair = ":$($PAT)"
    $encodedToken = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($basicAuthPair))

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("content-type", "application/json")
    $headers.Add("Authorization", "Basic $($encodedToken)")

    $createPoolUrl = "https://$($OrgUrl)/$($OrgName)" +
    "/_apis/distributedtask/elasticpools?poolName=$($PoolName)" +
    "&authorizeAllPipelines=true&autoProvisionProjectPools=false&projectId=$($ProjectGuid)&api-version=$($ApiVersion)"

    $getServiceEndpointUrl = "https://$($OrgUrl)/$($OrgName)/$($ProjectGuid)" +
        "/_apis/serviceendpoint/endpoints/?api-version=$($ApiVersion)"
    
    try {
        $response = Invoke-RestMethod -Method GET -Uri $getServiceEndpointUrl -Headers $headers
    } catch {
        Write-Error "`tThere was a problem fetching the unique id of your created Service Connection. This is likely a permissions error with the supplied Personal Access Token"
        exit 1
    }
    
    $serviceEndpointId = $($response.value | Where-Object { $_.Name -eq "$($ServiceConnectorName)" }).id

    $createPoolBody = @{
        agentInteractiveUI   = $false;
        azureId              = "/subscriptions/$($SubscriptionId)/resourceGroups/$($rgName)/providers/Microsoft.Compute/virtualMachineScaleSets/$($VMSSName)";
        desiredIdle          = $IdleCapacity;
        maxCapacity          = $MaxCapacity;
        osType               = 1;
        maxSavedNodeCount    = 0;
        recycleAfterEachUse  = $false;
        serviceEndpointId    = $($serviceEndpointId);
        serviceEndpointScope = $ProjectGuid;
        timeToLiveMinutes    = 30;
    }

    try {

        Write-Host "`tStarting the configuration of Pool '$PoolName'."
        
        $response = Invoke-WebRequest -Uri $createPoolUrl -Method 'POST' -Headers $headers -Body $($createPoolBody | ConvertTo-Json)
        
        if ($response.StatusCode -eq 203) {
            
            $errorMessage203 = "`tCreation of Pool '$($PoolName)' failed with error code 203. " +
                "Ensure Azure DevOps PAT has Agent Pools: Read & Manage Permissions"
            Write-Host $errorMessage203 -ForegroundColor Red
            return 1

        }
        
        else {
            Write-Host "`tCreation of Pool '$($PoolName)' was successful."
            return 0
        }
        
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $statusDescription = $_.Exception.Response.StatusDescription
        
        # Error: VMSS already in use by Pool
        if ($statusCode -eq 409) {
            Write-Host "`tCreation of Pool '$($PoolName)' failed, as Scale Set '$($VMSSName)' is already in use by an agent pool." -ForegroundColor Red
            return 1
        }
        
        # Error: Other
        else {
            Write-Host "`tCreate Pool '$($PoolName)' failed with error code $($statusCode): $($statusDescription)" -ForegroundColor Red
            return 1
        }
    }
    return 0
}

Function Get-AzureDevOpsConnection([string]$AzureDevOpsPAT, [string]$OrganizationUrl, [string]$OrganizationName, [string]$ProjectName, [string]$ProjectGuid, [string]$ServiceConnectorName) {

    $azureDevOpsAuthenicationHeader = @{Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$($AzureDevOpsPAT)")) }
    $uriOrga = "https://$($OrganizationUrl)/$($OrganizationName)"
    $uri = $UriOrga + "/" + $ProjectName + "/_apis/serviceendpoint/endpoints?endpointNames=" + $ServiceConnectorName + '&api-version=6.0-preview.4'
    $result = Invoke-WebRequest -Uri $uri -Method GET -Headers $azureDevOpsAuthenicationHeader -ContentType "application/json"
    $connector = ($result.Content | ConvertFrom-Json).value
    return $connector
}

Function Add-AzureDevOpsConnection([string]$AzureDevOpsPAT, [string]$OrganizationUrl, [string]$OrganizationName, [string]$ProjectName, [string]$ProjectGuid, [string]$ServiceConnectorName, $ServicePrincipal, [string] $ServicePrincipalKey, $Context) {

    $azureDevOpsAuthenicationHeader = @{Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$($AzureDevOpsPAT)")) }
    $uriOrga = "https://$($OrganizationUrl)/$($OrganizationName)"
    $uriAccount = $UriOrga + "/_apis/serviceendpoint/endpoints?api-version=6.0-preview.4"

    $connector = Get-AzureDevOpsConnection -AzureDevOpsPAT $AzureDevOpsPAT -OrganizationUrl $OrganizationUrl -OrganizationName $OrganizationName `
        -ProjectName $ProjectName -ProjectGuid $ProjectGuid -ServiceConnectorName $ServiceConnectorName

    # IF CONNECTOR DOESN'T EXIST CREATE ONE
    # OTHERWISE RETURN MESSAGE THAT ALREADY EXISTS AND RETURN CONNECTOR OBJECT
    if ($null -eq $connector) {
        $guid = (New-Guid).Guid

        $body = '{
            "data": {
                "scopeLevel":"Subscription",
                "subscriptionId":"'+ $Context.Subscription.Id + '",
                "environment":"AzureCloud",
                "subscriptionName":"'+ $Context.Subscription.Name + '",
                "scopeLevel":"Subscription",
                "creationMode":"Manual"
            },
            "description":"Service Connector",
            "id": "'+ $guid + '",
            "name": "'+ $ServiceConnectorName + '",
            "type": "AzureRM",
            "url": "https://management.azure.com/",
            "authorization": {
                "parameters": {
                    "tenantid":"'+$Context.Tenant.Id+'",
                    "servicePrincipalId":"'+$ServicePrincipal.AppId+'",
                    "authenticationType":"spnKey",
                    "servicePrincipalKey":"'+$ServicePrincipalKey+'"
                },
                "scheme":"ServicePrincipal"
            },
            "isShared": false,
            "isReady": true,
            "serviceEndpointProjectReferences": [
            {
            "projectReference": {
                "id": "'+$ProjectGuid+'",
                "name": "'+$ProjectName+'"
            },
            "name": "'+$ServiceConnectorName+'"
            }
        ]
        }'

        $patchBody = '{
            "allPipelines": {
                "authorized": true,
                "authorizedBy": null,
                "authorizedOn": null
            },
            "pipelines": null,
            "resource": {
                "id": "'+$guid+'",
                "type": "endpoint"
            }
        }'

        
        # Creating Azure DevOps Service Connection using RestAPI
        try {
            Write-Host "`t`tCreating Azure DevOps Service Connection '$($ServiceConnectorName)' for organization: '$($uriOrga)'."
            $serviceConnection = Invoke-RestMethod -Uri $uriAccount -Method POST -ContentType "application/json" -body $body -Headers $azureDevOpsAuthenicationHeader
            $patchURI = $UriOrga + "/" + $ProjectName + "/_apis/pipelines/pipelinePermissions/endpoint/" + $serviceConnection.id + '?api-version=5.1-preview.1'
            Write-host "`t`tUpdating Service Connection permissions for all pipelines"
            Invoke-RestMethod -Method PATCH -Uri $patchURI -Headers $azureDevOpsAuthenicationHeader -Body $patchBody -ContentType "application/json"
        } catch {
            Write-Error "`Managing Service Connection for $($OrgName) failed, ensure Azure DevOps PAT has Service Connections: Read, query, & manage"
            return $null
        }
    } else {
        Write-Host "`t`tAzure devops connector $($connector.name) already exists." -ForegroundColor Yellow
        return $connector
    }

    # GET NEWLY CREATED CONNECTOR AND RETURN THE OBJECT
    $connector = Get-AzureDevOpsConnection -AzureDevOpsPAT $AzureDevOpsPAT -OrganizationUrl $OrganizationUrl -OrganizationName $OrganizationName `
        -ProjectName $ProjectName -ProjectGuid $ProjectGuid -ServiceConnectorName $ServiceConnectorName -ServicePrincipal $ServicePrincipalName `
        -ServicePrincipalKey "" -Context $Context

    return $connector
}

Function Get-RandomCharacters($length, $characters) {
    $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
    $private:ofs = ""
    return [String]$characters[$random]
}
Function New-Password ([string]$inputString) {
    $characterArray = $inputString.ToCharArray()
    $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length
    $outputString = -join $scrambledStringArray
    return $outputString
}

Function Get-StringRandom {
    $s = Get-RandomCharacters -length 6 -characters 'abcdefghiklmnoprstuvwxyz'
    $s += Get-RandomCharacters -length 6 -characters 'ABCDEFGHKLMNOPRSTUVWXYZ'
    $s += Get-RandomCharacters -length 6 -characters '1234567890'
    $s += Get-RandomCharacters -length 7 -characters '!@#$%^&*()[]'

    return $s
}

Function IsAssignedKeyVaultRole ($ServicePrincipalObject, $AzureKeyVaultRoleDefinitionName, $Scope) {
    try {
        $role = Get-AzRoleAssignment -RoleDefinitionName $AzureKeyVaultRoleDefinitionName -Scope $Scope -ObjectId $ServicePrincipalObject.Id

        if ($role) {
            return $true
        } else {
            return $false
        }
    } catch {
        Write-Output "There was an error retrieving the role assignment."
        return $false
    }
}
Function Set-KeyVaultRoleAssignment ($ServicePrincipalObjectId, $AzureKeyVaultRoleDefinitionName, $Scope) {
    
    try {
        Write-Host "`t`tCreating role assignment for '$($ServicePrincipalObjectId)' with role definition '$($AzureKeyVaultRoleDefinitionName)'."
        $role = Get-AzRoleAssignment -RoleDefinitionName $AzureKeyVaultRoleDefinitionName -Scope $Scope -ObjectId $ServicePrincipalObjectId

        if (-not $role) {
            $result = New-AzRoleAssignment -RoleDefinitionName $AzureKeyVaultRoleDefinitionName -Scope $Scope -ObjectId $ServicePrincipalObjectId
        } else {
            Write-Host "`t`tRole assignment already exist on '$($ServicePrincipalObjectId)'" -ForegroundColor Yellow
            return 0
        }
    } catch {
        Write-Output $result
        return 1
    }

    # Sleep to ensure role assignment is completed
    $maxCount = 60
    $currentCount = 0
    Write-Host "`t`tWaiting for role assignment to propagate." -NoNewLine
    while ($currentCount -lt $maxCount) {
        Start-Sleep 10
        $role = Get-AzRoleAssignment -RoleDefinitionName $AzureKeyVaultRoleDefinitionName -Scope $Scope -ObjectId $ServicePrincipalObjectId
        if ($null -ne $role) {
            break
        }
        Write-Host "." -NoNewLine
        $currentCount++
    }
    Write-Host "`n`t`tRole assignment complete."
}

Function Set-KeyVaultRbac ($VaultObject) {

    try {
        $result = Update-AzKeyVault -EnableRbacAuthorization $true -VaultName $VaultObject.VaultName -ResourceGroupName $VaultObject.ResourceGroupName
        Write-Host "`t`tKey Vault enabled for RBAC Authorization."
    } catch {
        Write-Output $result
        return 1
    }
}

Function Get-ServicePrincipal ([string]$ServicePrincipalName, [string]$AppName, [string]$ENV, [string]$InstanceNumber, [string]$AdoSpnKeyFile, [string]$TenantId) {

    Write-Host "`tSearching for Service Principal '$ServicePrincipalName' in Azure AD"
    $servicePrincipal = Get-AzADServicePrincipal -DisplayName $ServicePrincipalName -ErrorAction Stop

    if ($null -eq $servicePrincipal) {
        Write-Host "`t`tService Principal '$ServicePrincipalName' not found in Azure AD"
        return $null
    }
    Write-Host "`t`tService Principal '$ServicePrincipalName` found in Azure AD"
    Write-Host "`tSearching for Service Principal '$ServicePrincipalName' credentials file, '$AdoSpnKeyFile'"
    if ((Test-Path -Path $AdoSpnKeyFile)) {
        Write-Host "`t`tService Principal '$ServicePrincipalName' credentials file found in, '$AdoSpnKeyFile'"
        $content = Get-Encrypted $AdoSpnKeyFile
        
        if ($content.Length -ne 2) {
            Write-Host "`t`tThe Service Principal '$ServicePrincipalName' credentials file doesn't have the expected content, AppId and AppSecret" -ForegroundColor Red
            return 1
        }
        $appId = $content[0]
        $key = $content[1] 
        
        if ($appId -ne $servicePrincipal.AppId) {
            Write-Host "`t`tService Principal '$ServicePrincipalName' credentials file AppId doesn't match the provided Service Principal AppId" -ForegroundColor Red
            return 1
        }
    } else {
        Write-Host "`t`tThe Service Principal '$ServicePrincipalName' credentials file doesn't exist or does not contain the expected content, AppId and AppSecret" -ForegroundColor Red
        return 1
    }

    # Try to login with the provided credentials
    Write-Host "`tTrying to connect to Azure using the provided Service Principal '$ServicePrincipalName' credentials"
    $currentErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Stop"
    try {
        $null = az login --service-principal --username $appId --p $key --tenant $TenantId --allow-no-subscriptions
        if ($? -eq $false) {
            throw 'Failed connecting to Azure using the provided credentials'
        }
    } catch {
        Write-Host "`t`tCouldn't connect to to Azure using the provided credentials" -ForegroundColor Red
        return 1
    }
    Write-Host "`t`tConnection to Azure using the provided credentials completed successfully"
    $ErrorActionPreference = $currentErrorActionPreference

    $result = @{"ServicePrincipal" = $servicePrincipal; "bstr" = $null; "ServicePrincipalKey" = $key }
    return $result
}

Function Set-GivenServicePrincipal([string]$ServicePrincipalAppId, [SecureString]$ClientSecret, [string]$AppName, 
    [string]$ENV, [string]$InstanceNumber, [string]$RedirectUrl, [switch]$useServicePrincipalCertificate) {
    
    try {
        $servicePrincipal = Get-AzADServicePrincipal -ApplicationId $ServicePrincipalAppId -ErrorAction Stop
        
        $webAppName = "app-" + $AppName + "-" + $ENV + "-" + $InstanceNumber
        $webAppRedirectUrl = "https://$($webAppName).azurewebsites.net/getAToken"
        $replyURLArray = @($RedirectUrl, $webAppRedirectUrl)
    
        if ($RedirectUrl -ne "") {
            $null = Update-AzADApplication -ApplicationId $servicePrincipal.AppId -ReplyUrls $replyURLArray -ErrorAction Stop
            Write-Host "`t`tService Principal '$($servicePrincipal.AppDisplayName)' reply urls configure to $($replyURLArray -join ",")"
        }

    } catch {

        Write-Host "`tThere was an error configuring the Application Registration." `
            + "`nThis is usually due to insufficient permissions assigned to the Service Principal" -ForegroundColor Red
        exit 1
    }

    if($useServicePrincipalCertificate) {
        $key = (New-AzADSpCredential -ServicePrincipalObject $servicePrincipal).SecretText
    }

    else {
        $key = ($ClientSecret | ConvertFrom-SecureString -AsPlainText)       
    }

    $result = @{"ServicePrincipal" = $servicePrincipal; "ServicePrincipalKey" = $key}

    return $result
}


Function Add-ServicePrincipal ([string]$ServicePrincipalName, [string]$AppName, [string]$ENV, 
    [string]$InstanceNumber, [string]$RedirectUrl, $Context) {

    $servicePrincipal = Get-AzADServicePrincipal -DisplayName $ServicePrincipalName -ErrorAction Stop

    if ($servicePrincipal) {
        Write-Host "`t`tAzure service principal already exists."  -ForegroundColor Yellow
        return $null
    }
    
    Write-Host "`tCreating the Service Principal '$($ServicePrincipalName)' in Azure AD '$($Context.Tenant.Id)'."
    try {
        $servicePrincipal = New-AzADServicePrincipal -DisplayName $ServicePrincipalName -ErrorAction Stop
        Write-Host "`t`tService Principal '$($ServicePrincipalName)' created successfully"
        
        # Redirect Urls
        $webAppName = "app-" + $AppName + "-" + $ENV + "-" + $InstanceNumber
        $webAppRedirectUrl = "https://$($webAppName).azurewebsites.net/getAToken"
        # $appRegistration = Get-AzADApplication -ApplicationId $servicePrincipal.AppId
        # $replyURLList = $appRegistration.ReplyUrl
        # $replyURLList.Add($RedirectUrl)
        # $replyURLList.Add($webAppRedirectUrl)
        $replyURLArray = @($RedirectUrl, $webAppRedirectUrl)
        
        # Update service principal with redirect urls
        if ($RedirectUrl -ne ""){
            $null = Update-AzADApplication -ApplicationId $servicePrincipal.AppId -ReplyUrls $replyURLArray -ErrorAction Stop
            Write-Host "`t`tService Principal '$($ServicePrincipalName)' reply urls configure to $($replyURLArray -join ",")"
        }
        
        # These value is used later when creating secrets in Key Vault
        $secret = $servicePrincipal.PasswordCredentials.SecretText
        Write-Host "`t`tWaiting 30 seconds for the Service Principal '$($ServicePrincipalName)' to propagate."
        Start-Sleep 30
    } catch {
        Write-Output $Error[0].Exception
        exit 1
    }

    $servicePrincipal = Get-AzADServicePrincipal -DisplayName $ServicePrincipalName
    $result = @{"ServicePrincipal" = $servicePrincipal; "bstr" = $bstr; "ServicePrincipalKey" = $secret }

    return $result
}

Function Add-Secrets ($ServicePrincipal, $Context, $KeyvaultName, [int]$DurationYears = 1, $SecretNames, $ExportJumpboxPwd = $false, $ExportAdoAgentPwd = $false, $adoAgentPwdFile, $jumpboxPwdFile) {
    $password = Get-StringRandom


    foreach ($secretName in $SecretNames) {

        switch ($secretName) {
            ClientId { $securesecret = $ServicePrincipal["ServicePrincipal"].AppId }
            ClientSecret { $securesecret = $ServicePrincipal["ServicePrincipalKey"] }
            ObjectId { $securesecret = $ServicePrincipal["ServicePrincipal"].Id }
            Authority { $securesecret = "https://login.microsoftonline.com/" + $Context.Tenant.Id }
            JumpboxPassword { $securesecret = New-Password $password }
            SessionSecret { $securesecret = New-Password $password }
            adoAgentPassword { $securesecret = New-Password $password }
        }

        # EXPORT JUMPBOX PASSWORD IF FLAG SET TO TRUE (USEFUL FOR TROUBLESHOOTING)
        if (($ExportJumpboxPwd -eq $true) -and ($secretName -eq 'JumpboxPassword')){
            $null = $securesecret | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File $jumpboxPwdFile -Force
        }

        # EXPORT ADOAGENT PASSWORD IF FLAG SET TO TRUE (USEFUL FOR TROUBLESHOOTING)
        if (($ExportAdoAgentPwd -eq $true) -and ($secretName -eq 'adoAgentPassword')){
            $null = $securesecret | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File $adoAgentPwdFile -Force
        }

        try {
            Write-Host "`tChecking secret for '$secretName'."
            $result = Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name $secretName
        } catch {
            #Write-Host $result
        }

        if (($null -eq $result) -or ($result -eq 0)) {
            Write-Host "`t`tCreating secret '$($secretName)' which expires in $($DurationYears) year(s)."
            $value = ConvertTo-SecureString $securesecret -AsPlainText -Force
            try {
                $result = Set-AzKeyVaultSecret -VaultName $KeyvaultName -Name $secretName -SecretValue $value -Expires (Get-Date).AddYears($DurationYears)
                Write-Host "`t`tSecret for '$($secretName)' created successfully."
            } catch {
                Write-Output $result
            }
        } else {
            Write-Host "`t`tSecret $($secretName) already exists. No updates will be performed" -ForegroundColor Yellow
        }
    }
}


Function Get-Value($YmlSourceFile, [string]$Name) {
    [int]$count = 0
    $varFile = Get-Content $YmlSourceFile

    foreach ($line in $varFile) {
        if ($line -cmatch $Name) {

            if ($line.Length -eq 0) {
                $count++
                continue
            }

            #CHECK IF FOLLOWING LINE IS A VALUE
            if (-not $varFile[$count + 1].Contains("value:")) {
                $count++
                continue
            }

            if (-not $line.Contains("- name:")) {
                $count++
                continue
            }

            $t = $line.Replace("- name:", "").Trim(" ")

            if ($t.Contains("#")) {
                $result = $t.Split("#")
                $t = $result[0].Trim()
            }

            if ($t -eq $Name) {
                $o = $varFile[$count + 1]
                #REMOVE COMMENTS
                if ($o.Contains("#")) {
                    $position = $o.IndexOf("#")
                    $o = $o.Substring(0, $position)
                }
                if ($o.Contains("value:")) {
                    $position = $o.IndexOf(":")
                    $o = $o.Substring($position + 1)
                }
                if ($o.Contains(" ")) {
                    $o = $o.Replace(" ", "")
                }
                return $o
            }
        }
        $count++
    }

    return $null
}

Function IsFunction([string]$source) {

    if ($source.Contains('$[')) {
        return $true
    }
    
    return $false
}

Function IsVariable([string]$source) {

    if (($source.Contains('$(') -or ($source.Contains("variables[")))) {
        return $true
    }
    
    return $false
}

Function ResolveVariable ([string]$VariableName, [string]$VariablesFile) {

    [bool]$bIsVariable = IsVariable -source $VariableName
    [bool]$bIsFunction = IsFunction -source $VariableName

    # IF PASSED VARIABLE NAME DOESN'T CONTAIN A VARIABLE OR FUNCTION JUST RETURN VALUE
    if ($bIsFunction -eq $false -and $bIsVariable -eq $false) {
        return $VariableName
    }

    $varList = $VariableName.Split("$")

    # ADD OUR $ VALUES BACK TO MAKE IDENTIFYING FUNCTIONS REMAINING IN THE LIST EASIER BELOW
    [int]$i = 0
    foreach ($_ in $varList) {
        $varList[$i] = $_.Replace("(", '$(')
        $i++
    }    

    $iterationCount = 0
    $bContinue = $true

    while ($bContinue) {

        [int]$count = 0

        foreach ($t in $varList) {

            if ($t.Length -eq 0) {
                $count++
                continue
            }

            # IS FUNCTION
            if (IsFunction -source $t) {
                $t = ResolveFunction -source $t
            }

            # IS VARIABLE
            if (IsVariable -source $t) {
    
                # FINDS NEXT VARIABLE NAME IN A GIVEN STRING
                $fName = GetNextVariable -source $t
    
                # GET VALUE OF VARIABLE
                $value = Get-Value -Name $fName -YmlSourceFile $VariablesFile
    
                # IN THIS CASE WE HAVE A NESTED FUNCTION WHICH WE DON'T SUPPORT
                # if (IsFunction -source $value){
                #     return $null
                # }
    
                $t = $t.Replace('$(' + $fName + ')', $value).Trim()
            }

            $varList[$count] = $t
            $count++
        }

        $iterationCount++
        if ($iterationCount -gt 50) {
            Write-Host "A potential circular variable reference has been detected. Returning Null" -ForegroundColor Yellow
            return $null
        }

        # CHECK OUR VARIABLES LIST AND SEE IF STILL HAVE VARIABLES OR FUNCTIONS 
        # IF WE HAVE A VARIABLE OR FUNCTION, CONTINUE
        if (-not (IsFunction $varList) -and !(IsVariable $varList)) {
            $bContinue = $false
        }

    }

    # REASSEMBLE OUR COLLECITON OF STRINGS INTO A STRING
    [string]$result = ""
    foreach ($_ in $varList) {
        $result += $_
    }

    return $result
}

Function ResolveFunction([string]$source) {

    $varList = $source.Split("$")

    # ADD OUR $ VALUES BACK TO MAKE IDENTIFYING FUNCTIONS REMAINING IN THE LIST EASIER BELOW
    [int]$i = 0
    foreach ($_ in $varList) {
        if (($_[0] -eq '[') -or ($_[0] -eq '(')) {
            $varList[$i] = $_.Insert(0, "$")
        }
        $i++
    }    

    $iterationCount = 0
    $bContinue = $true
    
    while ($bContinue) {

        [int]$count = 0

        foreach ($t in $varList) {

            if ($t.Length -eq 0) {
                $count++
                continue
            }

            # IS FUNCTION
            if (IsFunction -source $t) {
                if ($t.Contains("$[lower")) {
                    [int]$iStart = $t.IndexOf("(")
                    [int]$iEnd = $t.LastIndexOf(")") - $iStart + 1
                    
                    $result = $t.Substring($iStart, $iEnd)
        
                    # CHECK IF OUR RESULT CONTAINS A VARIABLE AND RESOLVE
                    if (IsVariable($result)) {
                        $t = $result.Replace("(variables[", "$").Replace("])", "").Replace("$'", '$(').Replace("'", ")")
                    }
                }
            }

            $varList[$count] = $t
            $count++
        }

        $iterationCount++
        if ($iterationCount -gt 50) {
            Write-Host "A potential circular variable reference has been detected. Returning Null" -ForegroundColor Yellow
            return $null
        }

        # CHECK OUR VARIABLES LIST AND SEE IF STILL HAVE FUNCTIONS 
        # IF WE HAVE A FUNCTION, CONTINUE
        if (-not (IsFunction $varList)) {
            $bContinue = $false
        }

        # REASSEMBLE OUR COLLECITON OF STRINGS INTO A STRING
        [string]$result = ""
        foreach ($_ in $varList) {
            $result += $_
        }
    }

    return $result
}
Function GetNextVariable([string]$source) {
    if ($source.Contains('$(')) {

        [int]$iStart = $source.IndexOf("(") + 1
        [int]$iEnd = $source.IndexOf(")") - $iStart

        $result = $source.Substring($iStart, $iEnd)
    }

    return $result
}

Function IsValidVmName ([string]$Name, [string]$OS = "Windows") {

    if ($OS -eq "Windows") {
        $maxLength = 15
    } else {
        $maxLength = 64
    }

    # CHECK LENGTH
    if ($Name.Length -gt $maxLength) {
        return $false
    }

    # CHECK IF INCLUDES SPECIAL CHARACTERS
    $specialChars = @('~', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '=', '+', '_', '[', ']', '{', '}', '\', '|', ';', ':', '.', ',', '<', '>', '/', '?', '"', "'")
    foreach ($_ in $specialChars) {
        if ($name.Contains($_)) {
            return $false
        }
    }

    # CHECK IF ENDS WITH A DASH
    if ($Name.EndsWith("-")) {
        Write-Host "Invalid Virtual Machine Name.  Virtual Machine name cannot end with a hypen (-)."
        return $false
    }

    return $true
}

Function Get-Encrypted ([string]$Path) {

    $result = @()

    if ((Test-Path -Path $Path)) {
        $content = Get-Content -Path $Path

        foreach ($_ in $content) {
            $encrypted = $_ | ConvertTo-SecureString
            $unencrypted = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((($encrypted))))
            $result += $unencrypted
        }

        return $result
    }    
}

Function Get-AdoProjectGuid ([string]$OrgUrl = "dev.azure.com", [string]$OrgName, [string]$ProjectName, [string]$PAT) {

    $encodedPAT = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$($PAT)"))
    $uriOrga = "https://$($OrgUrl)/$($OrgName)"
    $url = "$($uriOrga)/_apis/projects/?api-version=5.0-preview.3"
    try {
        $projects = (Invoke-RestMethod -Uri $url -Method 'GET' -Headers @{Authorization = "Basic $($encodedPAT)" }).value

        foreach ($_ in $Projects) {
            if ($_.name -eq $ProjectName) {
                return $_.id
            }
        }
    } catch {
        Write-Error "`tObtaining Project GUID failed."
    }

    return $null
}

Function Test-KeyvaultConfiguration ($VaultName, $ResourceGroupName, $ServicePrincipalObject, $AzureKeyVaultRoleDefinitionName, $Scope){

    $role = Get-AzRoleAssignment -RoleDefinitionName $AzureKeyVaultRoleDefinitionName -Scope $Scope -ObjectId $ServicePrincipalObject.Id
    if ($null -eq $role) {
        return 1
    }

    $vault = Get-AzKeyVault -VaultName $kvName -ResourceGroupName $rgName

    if (-not $vault.EnableRbacAuthorization) {
        return 1
    }

    return 0

    # Sleep to ensure role assignment is completed
    # $maxCount = 60
    # $currentCount = 0
    # Write-Host "`t`tWaiting for role assignment to propagate." -NoNewLine
    # while ($currentCount -lt $maxCount) {
    #     Start-Sleep 10
    #     $role = Get-AzRoleAssignment -RoleDefinitionName $AzureKeyVaultRoleDefinitionName -Scope $Scope -ObjectId $ServicePrincipalObject.Id
    #     if ($null -ne $role) {
    #         break
    #     }
    #     Write-Host "." -NoNewLine
    #     $currentCount++
    # }
    # Write-Host "`n`t`tRole assignment complete."    
}

Function Remove-Apim ([string]$Region, [string]$ServiceName, [string]$SubscriptionId){
    $token = Get-AzAccessToken

    $request = @{
        Method = 'DELETE'
        Uri    = "https://management.azure.com/subscriptions/$($subscriptionId)/providers/Microsoft.ApiManagement/locations/$($Region)/deletedservices/$($ServiceName)?api-version=2020-06-01-preview"
        Headers = @{
            Authorization = "Bearer $($token.Token)"
        }
    }

    Invoke-RestMethod @request
}