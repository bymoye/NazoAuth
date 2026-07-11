$ErrorActionPreference = "Stop"

$scriptPath = Join-Path $PSScriptRoot "..\scripts\deploy_live.ps1"
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $scriptPath,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) {
    throw "deploy_live.ps1 has parse errors: $($parseErrors -join '; ')"
}

$function = $ast.Find(
    {
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq "ConvertTo-ShellLiteral"
    },
    $true
)
if ($null -eq $function) {
    throw "ConvertTo-ShellLiteral was not found"
}

Invoke-Expression $function.Extent.Text

$emptyLiteral = ConvertTo-ShellLiteral ""
if ($emptyLiteral -ne "''") {
    throw "empty shell literal must be two single quotes, got: $emptyLiteral"
}

$quotedLiteral = ConvertTo-ShellLiteral "a'b"
if ($quotedLiteral -ne "'a'\''b'") {
    throw "single quote escaping changed unexpectedly: $quotedLiteral"
}

Write-Output "deploy_live shell literal tests passed"
