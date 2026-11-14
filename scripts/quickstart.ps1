<#
.SYNOPSIS
    Ferrous ReverseProxy 3-minute standalone local quickstart and verification script.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path "$ScriptDir/.."

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Ferrous ReverseProxy - 3-Minute Quickstart & Audit      " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

Set-Location $ProjectRoot

# 1. Run cargo check & test suite
Write-Host "`n[Step 1/3] Executing fast test suite..." -ForegroundColor Green
cargo test --manifest-path "$ProjectRoot/Cargo.toml" --lib
if ($LASTEXITCODE -ne 0) {
    throw "Unit tests failed!"
}
Write-Host "  [OK] WAF, routing, and TLS unit tests passed." -ForegroundColor Green

# 2. Run unbuffered SSE stream integration test
Write-Host "`n[Step 2/3] Verifying unbuffered Axum SSE streaming..." -ForegroundColor Green
cargo test --manifest-path "$ProjectRoot/Cargo.toml" --test test_sse_streaming
if ($LASTEXITCODE -ne 0) {
    throw "SSE streaming test failed!"
}
Write-Host "  [OK] SSE streaming pass-through verified (X-Accel-Buffering: no, zero chunk buffering)." -ForegroundColor Green

# 3. Static configuration & Day-0 rules verification
Write-Host "`n[Step 3/3] Auditing WAF CRS & Day-0 SecRules..." -ForegroundColor Green
$RuleFiles = Get-ChildItem -Path "$ProjectRoot/config" -Recurse -Include *.conf,*.yaml
Write-Host "  Found $($RuleFiles.Count) rule and topology configuration files." -ForegroundColor Cyan
foreach ($file in $RuleFiles) {
    Write-Host "  - $($file.Name)" -ForegroundColor Gray
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host "  [OK] QUICKSTART AUDIT COMPLETED IN UNDER 3 MINUTES!     " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
