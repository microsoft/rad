<#
	.NOTES
		==============================================================================================
		Copyright(c) Microsoft Corporation. All rights reserved.

		File:		Set-AkvSecrets.ps1

		Purpose:	Set Azure KeyVault Key Secrets

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
		Set Azure KeyVault Key Secrets.

	.DESCRIPTION
		Set Azure KeyVault Key Secrets.

		Deployment steps of the script are outlined below.
		1) Set Azure KeyVault Parameters
		2) Create Azure KeyVault Secret

	.PARAMETER keyVaultName
		Specify the Azure KeyVault Name output parameter.

	.PARAMETER keyVaultResourceId
		Specify the Azure KeyVault ResourceId output parameter.

	.PARAMETER keyVaultResourceGroup
		Specify the Azure KeyVault ResourceGroup output parameter.

	.EXAMPLE
		Default:
		C:\PS>.\KeyVault.akv.set.secrets.ps1
			-keyVaultName "$(keyVaultName)"
			-keyVaultResourceId "$(keyVaultResourceId)"
			-keyVaultResourceGroup "$(keyVaultResourceGroup)"
#>

#Requires -Version 5
#Requires -Module Az.KeyVault

[CmdletBinding()]
param
(
	[Parameter(Mandatory = $false)]
	[string]$keyVaultName,

	[Parameter(Mandatory = $false)]
	[string]$keyVaultResourceId,

	[Parameter(Mandatory = $false)]
	[string]$keyVaultResourceGroup
)

#region - KeyVault Parameters
if (-not [string]::IsNullOrWhiteSpace($keyVaultName))
{
	Write-Output "keyVaultName : $keyVaultName"
	$kvSecretParameters = @{ }

	#region - Azure KeyVault Parameters
	if (-not [string]::IsNullOrWhiteSpace($PSBoundParameters['keyVaultName']))
	{
		Write-Output "KeyVault Name: $keyVaultName"
		$kvSecretParameters.Add("KeyVault--Name--$($keyVaultName)", $($keyVaultName))
	}
	else
	{
		Write-Output "KeyVault Name: []"
	}

	if (-not [string]::IsNullOrWhiteSpace($PSBoundParameters['keyVaultResourceId']))
	{
		Write-Output "KeyVault ResourceId: $keyVaultResourceId"
		$kvSecretParameters.Add("KeyVault--ResourceId--$($keyVaultName)", $($keyVaultResourceId))
	}
	else
	{
		Write-Output "KeyVault ResourceId: []"
	}

	if (-not [string]::IsNullOrWhiteSpace($PSBoundParameters['keyVaultResourceGroup']))
	{
		Write-Output "KeyVault ResourceGroup: $keyVaultResourceGroup"
		$kvSecretParameters.Add("KeyVault--ResourceGroup--$($keyVaultName)", $($keyVaultResourceGroup))
	}
	else
	{
		Write-Output "KeyVault ResourceGroup: []"
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