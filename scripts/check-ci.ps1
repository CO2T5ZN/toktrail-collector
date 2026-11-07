# Windows-local equivalent of the CI native gate. Registers/runs/deletes only
# unique synthetic tasks owned by the existing integration tests. No real
# account state or vendor credentials are read by those fixtures.
param([string]$Go = 'go')
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Push-Location $repo
$oldProxy = $env:GOPROXY
$oldToolchain = $env:GOTOOLCHAIN
$oldScheduler = $env:TOKTRAIL_WINDOWS_SCHEDULER_E2E
$oldConnect = $env:TOKTRAIL_WINDOWS_CONNECT_E2E
try {
  $Go = (Get-Command $Go -CommandType Application -ErrorAction Stop).Source
  $actual = (& $Go env GOVERSION | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $actual -ne 'go1.24.13') {
    throw "CI toolchain mismatch: got $actual, need go1.24.13. Pass -Go with the matching executable."
  }
  $env:GOPROXY = 'off'
  $env:GOTOOLCHAIN = 'local'
  $logs = Join-Path $repo ('.local\ci-native-' + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $logs | Out-Null
  & $Go version
  & $Go vet ./...
  if ($LASTEXITCODE -ne 0) { throw 'go vet failed' }
  & $Go test ./... -count=1 '-timeout=3m' -v -json 2>&1 | Tee-Object -FilePath (Join-Path $logs 'full.jsonl')
  if ($LASTEXITCODE -ne 0) { throw 'full suite failed' }
  foreach ($entry in @(
    @{ Package='./internal/scheduler'; Test='TestWindowsSchedulerNativeIntegration'; Gate='TOKTRAIL_WINDOWS_SCHEDULER_E2E' },
    @{ Package='./cmd/toktrail'; Test='TestWindowsConnectNativeIntegration'; Gate='TOKTRAIL_WINDOWS_CONNECT_E2E' }
  )) {
    [Environment]::SetEnvironmentVariable($entry.Gate, '1', 'Process')
    $log = Join-Path $logs ($entry.Test + '.jsonl')
    & $Go test $entry.Package -run ('^' + $entry.Test + '$') -count=1 '-timeout=3m' -v -json 2>&1 | Tee-Object -FilePath $log
    if ($LASTEXITCODE -ne 0) { throw ($entry.Test + ' failed') }
    $passed = @(Get-Content -LiteralPath $log | ForEach-Object { try { $_ | ConvertFrom-Json } catch { $null } } | Where-Object { $_.Action -eq 'pass' -and $_.Test -eq $entry.Test })
    if ($passed.Count -ne 1) { throw ($entry.Test + ' must actually PASS; a skipped or unmatched test is not acceptance') }
    [Environment]::SetEnvironmentVariable($entry.Gate, $null, 'Process')
  }
  $stress = 'TestSQLiteCancellationReleasesDatabase'
  $stressLog = Join-Path $logs 'sqlite-stress.jsonl'
  & $Go test ./internal/source/hermessqlite ./internal/source/openclawsqlite ./internal/source/zcodesqlite -run ('^' + $stress + '$') -count=50 '-timeout=5m' -v -json 2>&1 | Tee-Object -FilePath $stressLog
  if ($LASTEXITCODE -ne 0) { throw 'SQLite cancel-resource stress failed' }
  $passed = @(Get-Content -LiteralPath $stressLog | ForEach-Object { try { $_ | ConvertFrom-Json } catch { $null } } | Where-Object { $_.Action -eq 'pass' -and $_.Test -eq $stress })
  foreach ($package in @('hermessqlite','openclawsqlite','zcodesqlite')) {
    $fullPackage = 'toktrail-collector/internal/source/' + $package
    if (@($passed | Where-Object { $_.Package -eq $fullPackage }).Count -ne 50) { throw ('expected 50 actual passes for ' + $fullPackage) }
  }
  & $Go test ./internal/scheduler ./internal/syncclient ./internal/syncretry -count=50 '-shuffle=on'
  if ($LASTEXITCODE -ne 0) { throw 'repeated regression failed' }
  & pwsh -NoProfile -File scripts/windows-smoke.ps1 -GoExe $Go 2>&1 | Tee-Object -FilePath (Join-Path $logs 'smoke.log')
  if ($LASTEXITCODE -ne 0) { throw 'Windows smoke failed' }
  Write-Host "PASS: Windows CI native gate and repeated regression. Logs: $logs"
} finally {
  $env:GOPROXY = $oldProxy
  $env:GOTOOLCHAIN = $oldToolchain
  $env:TOKTRAIL_WINDOWS_SCHEDULER_E2E = $oldScheduler
  $env:TOKTRAIL_WINDOWS_CONNECT_E2E = $oldConnect
  Pop-Location
}
