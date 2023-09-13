<#
	.NOTES
		==============================================================================================
		Copyright(c) Microsoft Corporation. All rights reserved.

		File:		Set-AkvSecrets.ps1

		Purpose:	Set Virtual Network Key Secrets

		Version: 	3.0.0.0 - 1st November 2020
		==============================================================================================

		DISCLAIMER
		==============================================================================================
		This script is not supported under any Microsoft standard support program or service.

		This script is provided AS IS without warranty of any kind.
		Microsoft further disclaims all implied warranties including, without limitation, any
		implied warranties of merchantability or of fitness for a particular purpose.

		The entire risk arising out of the use or performance of the script
		and documentation remains with you. In no event shall Microsoft, its authors,
		or anyone else involved in the creation, production, or delivery of the
		script be liable for any damages whatsoever (including, without limitation,
		damages for loss of business profits, business interruption, loss of business
		information, or other pecuniary loss) arising out of the use of or inability
		to use the sample scripts or documentation, even if Microsoft has been
		advised of the possibility of such damages.

		IMPORTANT
		==============================================================================================
		This script uses or is used to either create or sets passwords and secrets.
		All coded passwords or secrests supplied from input files must be created and provided by the customer.
		Ensure all passwords used by any script are generated and provided by the customer
		==============================================================================================

	.SYNOPSIS
		Set Virtual Network Key Secrets.

	.DESCRIPTION
		Set Virtual Network Key Secrets.

		Deployment steps of the script are outlined below.
		1) Set Azure KeyVault Parameters
		2) Set Virtual Network Parameters
		3) Create Azure KeyVault Secret

	.PARAMETER keyVaultName
		Specify the Azure KeyVault Name parameter.

	.PARAMETER virtualNetworkName
		Specify the Virtual Network Name output parameter.

	.PARAMETER virtualNetworkResourceId
		Specify the Virtual Network ResourceId output parameter.

	.PARAMETER virtualNetworkResourceGroup
		Specify the Virtual Network ResourceGroup output parameter.

	.EXAMPLE
		Default:
		C:\PS>.\Set-AkvSecrets.ps1
			-keyVaultName "$(keyVaultName)"
			-virtualNetworkName "$(virtualNetworkName)"
			-virtualNetworkResourceId "$(virtualNetworkResourceId)"
			-virtualNetworkResourceGroup "$(virtualNetworkResourceGroup)"
#>

#Requires -Module Az.KeyVault

[CmdletBinding()]
param
(
	[Parameter(Mandatory = $false)]
	[string]$keyVaultName,

	[Parameter(Mandatory = $false)]
	[string]$virtualNetworkName,

	[Parameter(Mandatory = $false)]
	[string]$virtualNetworkResourceId,

	[Parameter(Mandatory = $false)]
	[string]$virtualNetworkResourceGroup
)

#region - KeyVault Parameters
if (-not [string]::IsNullOrWhiteSpace($PSBoundParameters['keyVaultName']))
{
	Write-Output "KeyVault Name: $keyVaultName"
	$kvSecretParameters = @{ }

	#region - Virtual Network Parameters
	if (-not [string]::IsNullOrWhiteSpace($PSBoundParameters['virtualNetworkName']))
	{
		Write-Output "Virtual Network Name: $virtualNetworkName"
		$kvSecretParameters.Add("VirtualNetwork--Name--$($virtualNetworkName)", $($virtualNetworkName))
	}
	else
	{
		Write-Output "Virtual Network Name: []"
	}

	if (-not [string]::IsNullOrWhiteSpace($PSBoundParameters['virtualNetworkResourceId']))
	{
		Write-Output "Virtual Network ResourceId: $virtualNetworkResourceId"
		$kvSecretParameters.Add("VirtualNetwork--ResourceId--$($virtualNetworkName)", $($virtualNetworkResourceId))
	}
	else
	{
		Write-Output "Virtual Network ResourceId: []"
	}

	if (-not [string]::IsNullOrWhiteSpace($PSBoundParameters['virtualNetworkResourceGroup']))
	{
		Write-Output "Virtual Network ResourceGroup: $virtualNetworkResourceGroup"
		$kvSecretParameters.Add("VirtualNetwork--ResourceGroup--$($virtualNetworkName)", $($virtualNetworkResourceGroup))
	}
	else
	{
		Write-Output "Virtual Network ResourceGroup: []"
	}
	#endregion

	#region - Set Azure KeyVault Secret
	$kvSecretParameters.Keys | ForEach-Object {
		$key = $psitem
		$value = $kvSecretParameters.Item($psitem)

		if (-not [string]::IsNullOrWhiteSpace($value))
		{
			Write-Output "KeyVault Secret: $key : $value"
			$value = $kvSecretParameters.Item($psitem)
			$paramSetAzKeyVaultSecret = @{
				VaultName   = $keyVaultName
				Name        = $key
				SecretValue = (ConvertTo-SecureString $value -AsPlainText -Force)
				Verbose     = $true
			}
			Set-AzKeyVaultSecret @paramSetAzKeyVaultSecret
		}
		else
		{
			Write-Output "KeyVault Secret: $key - []"
		}
	}
	#endregion
}
else
{
	Write-Output "KeyVault Name: []"
}
#endregion