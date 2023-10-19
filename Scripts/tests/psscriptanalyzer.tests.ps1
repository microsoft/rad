param (
    [Parameter(Mandatory)]
    [string] $File
)

BeforeDiscovery {
    $fileLeaf = (Split-Path -Path $File -Leaf)
    
    $edgeCases = @{ 
        "Bootstrap-Ado.ps1" = "PSAvoidUsingConvertToSecureStringWithPlainText"
        "Bootstrap-Github.ps1" = "PSAvoidUsingConvertToSecureStringWithPlainText"        
    }
    
    if($edgeCases.keys.Contains($fileLeaf))
    {
        $analysis = Invoke-ScriptAnalyzer -Path $File -Settings @{ ExcludeRules=@( "$($edgeCases[$fileLeaf])" ) }
    }

    else {
        $analysis = Invoke-ScriptAnalyzer -Path $File
    }
    
}

foreach ($violation in $analysis) { 
    Describe "$($violation.ScriptName) violation on line $($violation.Line)" { 
        It "is not an Error. Violation message: $($violation.Message)" -TestCases @{ Violation = $violation } { # <- we pass $violation data to the test
            $violation.Severity | Should -Not -Be "Error"
        }
    }
}