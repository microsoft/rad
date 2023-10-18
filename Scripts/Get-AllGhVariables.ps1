<#
    .SYNOPSIS
        Searches the specified GitHub Actions Variables env file and returns all variables and values as a hashtable.

    .PARAMETER VariablesFile
        Full path to the variables file

    .PARAMETER VariableName
        Name of the variable to find in the variables file
#>

[CmdletBinding()]
param
(
    [Parameter(Mandatory=$false)]
    [string] $VariablesFile = "..\\Variables-Ring0.env"
)

# DETERMINE IF VARIABLE FILE IS FROM ADO OR GITHUB
if ($VariablesFile.Contains(".env")){
    $type = "Github"
} else {
    $type = "Ado"
}

$values = @{}
$result = @{}
$varFile = Get-Content $VariablesFile

foreach ($line in $varFile){
    # FIND FIRST INSTANCE OF THE EQUALS AND ONLY SPLIT THERE
    $iSplit = $line.IndexOf("=")
    if ($iSplit -ne -1){
        $t = $line.Substring(0, $iSplit)
    } else{
        $t = $null
    }
    
    if (($line.Length -eq 0) -or ($line.Contains("#"))){
        $count++
        continue
    }

    if ((!$line.Contains("=") -or ($line.Contains("#")))){
        $count++
        continue
    }

    # FIND FIRST INSTANCE OF THE EQUALS AND ONLY SPLIT THERE
    $iSplit = $line.IndexOf("=")
    $key = $line.Substring(0, $iSplit).Trim()
    $value = $line.Substring($iSplit+1).Trim()

    if ($values.ContainsKey($key) -eq $false){
        $values.add($key, $value)
    } else {
        Write-Host "Key $($t) seems to be a duplicate.  Skipping"
    }    
}

foreach ($k in $values.Keys){
    if ($values[$k].Contains('${')) {
        $r = &$PSScriptRoot\Get-GhVariableValue.ps1 -VariablesFile $VariablesFile -VariableName $k
        $result.add($k, $r)
    }
    else {
        $result.add($k, $values[$k])
    }
}

return $result