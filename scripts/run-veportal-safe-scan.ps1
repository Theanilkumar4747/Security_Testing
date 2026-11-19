param(
    [string]$Url = "https://pp-dev.veportal.in/client/dashboard"
)

$ErrorActionPreference = "Stop"
$approvedHost = "pp-dev.veportal.in"
$parsedUrl = [Uri]$Url
if ($parsedUrl.Scheme -ne "https" -or $parsedUrl.Host -ne $approvedHost) {
    throw "This safe scan runner only allows HTTPS on $approvedHost."
}

$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {
    $env:SCAN_ALLOWED_HOSTS = $approvedHost
    & mvn -q -DskipTests package
    if ($LASTEXITCODE -ne 0) {
        throw "Maven package failed with exit code $LASTEXITCODE."
    }

    Write-Host "Running ZAP baseline (passive) and the Selenium dashboard check."
    Write-Host "The login check submits one invalid username containing a quote and an invalid password; it does not attempt authentication bypass."
    & java -jar "target/security-framework.jar" `
        "--scanners=zap,selenium-dashboard" `
        "--url=$Url" `
        "--no-gate" `
        "--no-publish" `
        "--formats=html,json,sarif" `
        "--out=target/security-reports"
    if ($LASTEXITCODE -ne 0) {
        throw "Security scan failed with exit code $LASTEXITCODE."
    }
    Write-Host "Reports: target/security-reports/security-report.html, security-report.json, security-report.sarif"
}
finally {
    Pop-Location
}
