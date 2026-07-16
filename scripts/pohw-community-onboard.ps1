$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
$Python = Get-Command python3 -ErrorAction SilentlyContinue
if ($null -eq $Python) {
    $Python = Get-Command python -ErrorAction SilentlyContinue
}
if ($null -eq $Python) {
    Write-Error "Python 3 is required for the source-first onboarding check."
    exit 1
}

& $Python.Source (Join-Path $ScriptDir "pohw-community-onboarding.py") `
    @args --repo-root $RepoRoot
exit $LASTEXITCODE
