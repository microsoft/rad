<#
    .SYNOPSIS
        Searches the specified GitHub Actions Variables env file for the specified variable.

    .PARAMETER VariablesFile
        Full path to the variables file

    .PARAMETER VariableName
        Name of the variable to find in the variables file
#>

[CmdletBinding()]
param
(
    [Parameter(Mandatory=$false)]
    [string] $VariablesFile = "..\\Variables-Ring0.env",

    [Parameter(Mandatory)]
    [string] $VariableName,

    [switch] $SimpleCheck

)

Function Get-Value($EnvSourceFile, [string]$Name){
    [int]$count = 0
    $varFile = Get-Content $EnvSourceFile

    foreach ($line in $varFile){
        # FIND FIRST INSTANCE OF THE EQUALS AND ONLY SPLIT THERE
        $iSplit = $line.IndexOf("=")
        if ($iSplit -ne -1){
            $t = $line.Substring(0, $iSplit)
        } else{
            $t = $null
        }
       
        if ($t -eq $Name){

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
            $t = $line.Substring($iSplit+1)
            return $t.Trim()
        }
        $count++
    }

    return $null
}

Function IsFunction([string]$source){

    if ($source.Contains('$[')){
        return $true
    }
    
    return $false
}

Function IsVariable([string]$source){

    if ( ($source.Contains('$(')) -or ($source.Contains('${')) -or ($source.Contains("variables["))){
        return $true
    }
    
    return $false
}

Function ResolveVariable ([string]$VariableName, [string]$VariablesFile){

    [bool]$bIsVariable = IsVariable -source $VariableName
    [bool]$bIsFunction = IsFunction -source $VariableName

    # IF PASSED VARIABLE NAME DOESN'T CONTAIN A VARIABLE OR FUNCTION JUST RETURN VALUE
    if ($bIsFunction -eq $false -and $bIsVariable -eq $false){
        return $VariableName
    }

    if ($VariableName.Contains('${')) {
        $bContinue = $true
        $loopCount = 0
    
        $o = $VariableName
        while($bContinue){
    
            $i = $o.IndexOf("$")
            if ($o[$i+1] -eq "{"){
                $bIndex = $i +2
                $eIndex = $o.IndexOf("}", $bIndex) - $bIndex
                $result = $o.Substring($bIndex, $eIndex)
    
                $foo = Get-Value -EnvSourceFile $VariablesFile -Name $result
                $s = '${' + $result + '}'
                $o = $o.Replace($s, $foo)
            } else{
                $bContinue = $false
            }
            $iterationCount++

            if ($iterationCount -gt 50){
                Write-Host "A potential circular variable reference has been detected. Returning Null" -ForegroundColor Yellow
                return $null
            }
        }
    }
    else {
        $o = Get-Value -EnvSourceFile $VariablesFile -Name $VariableName
    }

    return $o
}

Function ResolveFunction([string]$source){

    $varList = $source.Split("$")

    # ADD OUR $ VALUES BACK TO MAKE IDENTIFYING FUNCTIONS REMAINING IN THE LIST EASIER BELOW
    [int]$i=0
    foreach ($_ in $varList){
        if (($_[0] -eq '[') -or ($_[0] -eq '(')){
            $varList[$i] = $_.Insert(0,"$")
        }
        $i++
    }    

    $iterationCount = 0
    $bContinue = $true
    
    while($bContinue){

        [int]$count=0

        foreach ($t in $varList){

            if ($t.Length -eq 0){
                $count++
                continue
            }

            # IS FUNCTION
            if (IsFunction -source $t){
                if ($t.Contains("$[lower")){
                    [int]$iStart = $t.IndexOf("(")
                    [int]$iEnd = $t.LastIndexOf(")") - $iStart +1
                    
                    $result = $t.Substring($iStart, $iEnd)
        
                    # CHECK IF OUR RESULT CONTAINS A VARIABLE AND RESOLVE
                    if (IsVariable($result)){
                        $t = $result.Replace("(variables[","$").Replace("])","").Replace("$'",'$(').Replace("'",")")
                    }
                }
            }

            $varList[$count] = $t
            $count++
        }

        $iterationCount++
        if ($iterationCount -gt 50){
            Write-Host "A potential circular variable reference has been detected. Returning Null" -ForegroundColor Yellow
            return $null
        }

        # CHECK OUR VARIABLES LIST AND SEE IF STILL HAVE FUNCTIONS 
        # IF WE HAVE A FUNCTION, CONTINUE
        if (!(IsFunction $varList)){
            $bContinue = $false
        }

        # REASSEMBLE OUR COLLECITON OF STRINGS INTO A STRING
        [string]$result = ""
        foreach ($_ in $varList){
            $result += $_
        }
    }

    return $result
}

Function GetNextVariable([string]$source){
    if ($source.Contains('${')){

        [int]$iStart = $source.IndexOf("{") + 1
        [int]$iEnd = $source.IndexOf("}") - $iStart

        $result = $source.Substring($iStart, $iEnd)
    }

    return $result
}


$v = Get-Value -Name $VariableName -EnvSourceFile $VariablesFile

if($SimpleCheck){
    if ($null -eq $v){
        return 1
    }else{
        return 0
    }
} else{
    $result = ResolveVariable -VariableName $v -VariablesFile $VariablesFile
}

return $result