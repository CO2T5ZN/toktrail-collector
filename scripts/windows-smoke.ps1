#Requires -Version 5.1
<#
.SYNOPSIS
Windows smoke test for the toktrail collector CLI.

.DESCRIPTION
Build the real collector executable with the local Go toolchain and exercise
the offline CLI surface (version, help, scan, preview, export, privacy,
sources, doctor) against synthetic usage-json fixtures, verifying the exit
code and the output contract of every native invocation step by step.

Scope (deliberately bounded, do not over-read the result):
- This is a CLI smoke test ONLY, on a real Windows runner with a real build.
- It does NOT cover `toktrail connect`: the connect flow against a local mock
  server is already covered by TestRunConnectCLIIntegration
  (cmd/toktrail/connect_test.go). A real connect + scheduled-service E2E is a
  separate task.
- It does NOT cover the installer / release chain (cmd/toktrail-installer,
  scripts/release.sh, signed manifests).
- It never touches user data, credentials, or the network. Only offline
  subcommands are invoked (doctor runs without --check-server), and the Go
  build runs offline with GOPROXY=off, GOTOOLCHAIN=local and the vendored
  dependencies.

Isolation model:
- All work happens under one unique temp root created by this script:
    <temp>\toktrail-smoke-<stamp>-<pid>-<rand>\
- The root is claimed exclusively: if the candidate path already exists the
  run fails immediately (never reuse), the root directory is created without
  -Force, and a placeholder file is then opened with CreateNew (atomic
  no-clobber) to claim it. Only after that claim succeeds is the root
  registered for cleanup; cleanup also refuses to delete a root that lacks
  the placeholder, so files this script did not create are never removed.
- The runtime tree (home, state, data, out, bin) lives inside a working
  directory whose name contains spaces and non-ASCII characters. That name is
  built from [char] code points, so this file stays pure ASCII and has no
  source-encoding dependency.
- HOME, USERPROFILE, APPDATA, LOCALAPPDATA and TOKTRAIL_HOME are overridden
  for every child process, and every stateful subcommand additionally gets an
  explicit --state-dir that points into the isolated tree.
- The Go build cache and GOPATH live on ASCII paths under the same temp root;
  the built executable, fixtures and state live under the non-ASCII path, so
  the product surface is what exercises Unicode.
- Cleanup removes ONLY the unique temp root created by this script, guarded by
  a temp-base prefix check, a leaf-name shape check, and the placeholder
  marker left by this run. Pass -KeepTemp to keep it for debugging.

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows-smoke.ps1

.EXAMPLE
pwsh -NoProfile -File scripts/windows-smoke.ps1 -KeepTemp

.NOTES
Exit codes: 0 = all verified steps passed; 1 = a step, an assertion, or the
cleanup failed. Requires Windows PowerShell 5.1 or PowerShell 7+ on Windows.
On any other OS the script refuses to run unless -AllowNonWindows is passed
(validation mode for this script itself; it is NOT a Windows smoke result).
#>
[CmdletBinding()]
param(
    # Go executable to build with. Default: whatever `go` resolves to on PATH.
    [string]$GoExe = 'go',

    # Repository root that contains go.mod. Default: parent of this script.
    [string]$RepoRoot = '',

    # Keep the temp root (for debugging failures) instead of removing it.
    [switch]$KeepTemp,

    # Allow running on a non-Windows OS. Script-validation mode only: the
    # smoke target is Windows; a pass here does not certify Windows behavior.
    [switch]$AllowNonWindows
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Script state
# ---------------------------------------------------------------------------

$script:TempRoot = $null            # unique root created by this script only
$script:TempRootMarkerName = 'toktrail-smoke-root.placeholder'  # exclusive claim token
$script:CurrentStep = 'startup'     # label of the step being executed
$script:ExitCode = 0                # final exit code (0 pass, 1 fail)
$script:VerifiedSteps = 0           # count of verified steps for the summary
$script:LastNativeOutput = ''       # last native command output (for errors)
$script:UnicodeOutputReliable = $false  # [Console]::OutputEncoding == UTF-8
$script:LocationPushed = $false     # Push-Location bookkeeping
$script:EnvBackup = @{}             # original values of overridden env vars

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Write-SmokeLog {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host ('[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Message)
}

function Set-SmokeEnv {
    # Override a process environment variable for child processes, recording
    # the original value so the finally block can restore it.
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Value
    )
    if (-not $script:EnvBackup.ContainsKey($Name)) {
        $script:EnvBackup[$Name] = [Environment]::GetEnvironmentVariable($Name, 'Process')
    }
    [Environment]::SetEnvironmentVariable($Name, $Value, 'Process')
}

function Restore-SmokeEnv {
    foreach ($key in @($script:EnvBackup.Keys)) {
        [Environment]::SetEnvironmentVariable($key, $script:EnvBackup[$key], 'Process')
    }
    $script:EnvBackup = @{}
}

function New-SmokeDirectory {
    # Exclusive directory creation: NO -Force, so an already existing path is
    # a loud error instead of silent reuse. Every directory this script needs
    # lives inside the freshly claimed temp root, so legitimate re-creation
    # never happens; a collision must abort, not adopt.
    param([Parameter(Mandatory = $true)][string]$Path)
    New-Item -ItemType Directory -Path $Path | Out-Null
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "directory was not created: $Path"
    }
    return $Path
}

function Write-SmokeAsciiFile {
    # Write pure-ASCII content with no BOM (the Go JSON loader rejects a BOM;
    # ASCII encoding also fails loudly if non-ASCII ever leaks into a fixture).
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )
    $parent = Split-Path -Parent $Path
    if ([string]::IsNullOrEmpty($parent)) { throw "no parent directory for: $Path" }
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw "fixture parent directory does not exist: $parent"
    }
    [System.IO.File]::WriteAllText($Path, $Content, [System.Text.Encoding]::ASCII)
    Write-SmokeLog ("fixture written: " + $Path)
}

function Format-SmokeCommandLine {
    # Human-readable rendering of a native invocation (for the audit log).
    param(
        [Parameter(Mandatory = $true)][string]$ExePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    $parts = @($ExePath)
    foreach ($argument in $Arguments) {
        if ($argument -match '\s') { $parts += ('"' + $argument + '"') } else { $parts += $argument }
    }
    return ($parts -join ' ')
}

function Invoke-SmokeNative {
    # Run one native command, capture stdout+stderr, log the output, and check
    # the exit code against the expectation. Returns the combined output text
    # with line endings normalized to "`n".
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$ExePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [int]$ExpectedExitCode = 0
    )
    $script:CurrentStep = $Label
    Write-SmokeLog ("step [" + ($script:VerifiedSteps + 1) + "]: " + $Label)
    Write-SmokeLog ("  run: " + (Format-SmokeCommandLine -ExePath $ExePath -Arguments $Arguments))

    # PowerShell 5.1 turns redirected native stderr into ErrorRecords and can
    # raise a terminating NativeCommandError while $ErrorActionPreference is
    # 'Stop'; lower it for the duration of the redirection.
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $raw = & $ExePath @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $previousPreference

    $lines = @()
    foreach ($item in @($raw)) {
        if ($null -ne $item) { $lines += [string]$item }
    }
    $text = ($lines -join "`n")
    $script:LastNativeOutput = $text

    if ($lines.Count -gt 0) {
        foreach ($line in $lines) { Write-SmokeLog ("  | " + $line) }
    } else {
        Write-SmokeLog '  | (no output)'
    }

    if ($exitCode -ne $ExpectedExitCode) {
        throw ("native command exited with code {0}, expected {1}: {2}" -f $exitCode, $ExpectedExitCode, (Format-SmokeCommandLine -ExePath $ExePath -Arguments $Arguments))
    }
    $script:VerifiedSteps++
    return $text
}

function Assert-SmokeTrue {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw ("assertion failed: " + $Message)
    }
    $script:VerifiedSteps++
}

function Assert-SmokeMatch {
    # Assert that $Text matches a .NET regular expression. Prefer (?m)^...$
    # line pins for exact output contracts.
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if ($Text -notmatch $Pattern) {
        throw ("assertion failed: " + $Message + "; expected pattern: " + $Pattern + "; actual output:`n" + $Text)
    }
    $script:VerifiedSteps++
}

function New-SmokeUnicodeDirName {
    # "Smoke Root <U+00DC>n<U+00EF>code <U+6D4B><U+8BD5> dir" -- spaces plus
    # Latin-1 supplement plus CJK, built from code points so this source file
    # stays pure ASCII (PowerShell 5.1 reads BOM-less files as ANSI).
    $uUmlaut = [string][char]0x00DC    # LATIN CAPITAL LETTER U WITH DIAERESIS
    $iDiaeresis = [string][char]0x00EF # LATIN SMALL LETTER I WITH DIAERESIS
    $cjkMeasure = [string][char]0x6D4B # CJK UNIFIED IDEOGRAPH (measure)
    $cjkTest = [string][char]0x8BD5    # CJK UNIFIED IDEOGRAPH (test)
    return ('Smoke Root ' + $uUmlaut + 'n' + $iDiaeresis + 'code ' + $cjkMeasure + $cjkTest + ' dir')
}

function Remove-SmokeTempRoot {
    # Remove ONLY the temp root this script created. Guarded by a temp-base
    # prefix check, a leaf-name shape check, and the placeholder marker this
    # run wrote when it claimed the root, so a corrupted path variable or a
    # root not owned by this run can never be deleted.
    if ($null -eq $script:TempRoot) { return }
    $tempBase = [System.IO.Path]::GetTempPath()
    $full = [System.IO.Path]::GetFullPath($script:TempRoot)
    if (-not $full.StartsWith($tempBase, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ("refusing to remove a path outside the temp base: " + $full)
    }
    $leaf = Split-Path -Leaf $full
    if ($leaf -notlike 'toktrail-smoke-*') {
        throw ("refusing to remove an unexpected temp root leaf: " + $leaf)
    }
    $markerPath = Join-Path $full $script:TempRootMarkerName
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
        throw ("refusing to remove a temp root without the placeholder marker of this run: " + $full)
    }
    if (-not (Test-Path -LiteralPath $full)) { return }
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction Stop
        } catch {
            if ($attempt -ge 3) { throw }
            Start-Sleep -Milliseconds 500
        }
        if (-not (Test-Path -LiteralPath $full)) { return }
    }
    throw ("temp root still exists after removal attempts: " + $full)
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

try {
    $script:CurrentStep = 'preflight'

    $onWindows = ([Environment]::GetEnvironmentVariable('OS', 'Process') -eq 'Windows_NT')
    if (-not $onWindows -and -not $AllowNonWindows) {
        throw ('this smoke script targets Windows (env:OS=' + [Environment]::GetEnvironmentVariable('OS', 'Process') + '); pass -AllowNonWindows only to validate the script itself on another OS')
    }
    if (-not $onWindows) {
        Write-SmokeLog 'WARNING: non-Windows validation mode (-AllowNonWindows); a pass here is NOT a Windows smoke result'
    }

    if ([string]::IsNullOrEmpty($RepoRoot)) { $RepoRoot = Split-Path -Parent $PSScriptRoot }
    $RepoRoot = [System.IO.Path]::GetFullPath($RepoRoot)
    Assert-SmokeTrue -Condition (Test-Path -LiteralPath (Join-Path $RepoRoot 'go.mod')) -Message ("go.mod not found under repo root: " + $RepoRoot)
    Assert-SmokeTrue -Condition (Test-Path -LiteralPath (Join-Path $RepoRoot 'vendor')) -Message ("vendor/ not found under repo root (offline build requires vendored deps): " + $RepoRoot)
    Write-SmokeLog ("repo root: " + $RepoRoot)

    $goCommand = Get-Command -Name $GoExe -ErrorAction SilentlyContinue
    if ($null -eq $goCommand) {
        throw ("go executable not found via '" + $GoExe + "'; install Go or pass -GoExe <full path to go>")
    }
    $goExePath = $goCommand.Source
    Write-SmokeLog ("go executable: " + $goExePath)

    # Decode native output as UTF-8 (Go writes UTF-8). When this cannot be set
    # (exotic hosts), non-ASCII output assertions are skipped instead of
    # producing mojibake false failures; filesystem assertions still cover the
    # non-ASCII paths.
    try {
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        $script:UnicodeOutputReliable = $true
        Write-SmokeLog 'console output encoding set to UTF-8'
    } catch {
        Write-SmokeLog ("warning: could not set console output encoding to UTF-8 (" + $_.Exception.Message + "); non-ASCII output assertions will be skipped")
    }

    # --- isolated temp tree ------------------------------------------------
    $script:CurrentStep = 'create temp tree'
    $tempBase = [System.IO.Path]::GetTempPath()
    $tempLeaf = 'toktrail-smoke-{0}-{1}-{2}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), $PID, ((Get-Random -Maximum 16777215).ToString('x6'))
    $candidateRoot = Join-Path $tempBase $tempLeaf

    # Claim the root exclusively. A collision with an existing path is a hard
    # failure (never reuse an existing root, never delete unknown files): the
    # run aborts before anything is created inside it, and the root is only
    # registered for cleanup AFTER the placeholder claim succeeds.
    if (Test-Path -LiteralPath $candidateRoot) {
        throw ('temp root candidate already exists; refusing to reuse or remove it: ' + $candidateRoot)
    }
    [void](New-SmokeDirectory -Path $candidateRoot)  # exclusive: no -Force, fails if the path appears meanwhile
    $markerPath = Join-Path $candidateRoot $script:TempRootMarkerName
    try {
        # CreateNew is an atomic no-clobber open: it fails if the file already
        # exists, which is what makes the claim reliable even under a race.
        $markerStream = [System.IO.File]::Open($markerPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try {
            $markerBytes = [System.Text.Encoding]::ASCII.GetBytes(('toktrail smoke root placeholder; created={0}; pid={1}' -f (Get-Date -Format 'o'), $PID))
            $markerStream.Write($markerBytes, 0, $markerBytes.Length)
        } finally {
            $markerStream.Dispose()
        }
    } catch {
        # The root is NOT registered for cleanup (TempRoot stays $null): we do
        # not own it. Leaking one empty directory into the system temp on this
        # pathological path is the safe side of the trade.
        throw ('failed to exclusively claim the temp root with the placeholder file (path already in use or not writable): ' + $candidateRoot + ' (' + $_.Exception.Message + ')')
    }
    $script:TempRoot = $candidateRoot
    Write-SmokeLog ("temp root claimed exclusively: " + $script:TempRoot)

    # Toolchain-internal paths stay ASCII; product-facing paths below are not.
    $goCacheDir = New-SmokeDirectory -Path (Join-Path $script:TempRoot 'go-cache')
    $goPathDir = New-SmokeDirectory -Path (Join-Path $script:TempRoot 'go-path')

    $workRoot = New-SmokeDirectory -Path (Join-Path $script:TempRoot (New-SmokeUnicodeDirName))
    $homeDir = New-SmokeDirectory -Path (Join-Path $workRoot 'home')
    $stateDir = New-SmokeDirectory -Path (Join-Path $workRoot 'state')
    $dataDir = New-SmokeDirectory -Path (Join-Path $workRoot 'data')
    $outDir = New-SmokeDirectory -Path (Join-Path $workRoot 'out')   # export requires the --out parent to exist
    $binDir = New-SmokeDirectory -Path (Join-Path $workRoot 'bin')
    [void](New-SmokeDirectory -Path (Join-Path $homeDir 'AppDataRoaming'))
    [void](New-SmokeDirectory -Path (Join-Path $homeDir 'AppDataLocal'))
    Write-SmokeLog ("temp root: " + $script:TempRoot)
    Write-SmokeLog ("working root (spaces + non-ASCII): " + $workRoot)

    # --- environment isolation (restored in finally) -----------------------
    Set-SmokeEnv -Name 'TOKTRAIL_HOME' -Value $stateDir
    Set-SmokeEnv -Name 'HOME' -Value $homeDir
    Set-SmokeEnv -Name 'USERPROFILE' -Value $homeDir
    Set-SmokeEnv -Name 'APPDATA' -Value (Join-Path $homeDir 'AppDataRoaming')
    Set-SmokeEnv -Name 'LOCALAPPDATA' -Value (Join-Path $homeDir 'AppDataLocal')
    # Offline, hermetic Go build (vendored deps; no proxy, no toolchain
    # download, no workspace/user go env file, no cgo).
    Set-SmokeEnv -Name 'GOFLAGS' -Value '-mod=vendor'
    Set-SmokeEnv -Name 'GOPROXY' -Value 'off'
    Set-SmokeEnv -Name 'GOTOOLCHAIN' -Value 'local'
    Set-SmokeEnv -Name 'GOENV' -Value 'off'
    Set-SmokeEnv -Name 'GOWORK' -Value 'off'
    Set-SmokeEnv -Name 'CGO_ENABLED' -Value '0'
    Set-SmokeEnv -Name 'GOCACHE' -Value $goCacheDir
    Set-SmokeEnv -Name 'GOPATH' -Value $goPathDir

    # --- synthetic fixtures (field set mirrors the canonical example in
    #     internal/source/usagejson/integration_test.go around line 180) -----
    $script:CurrentStep = 'write fixtures'
    $fixtureValid = Join-Path $dataDir 'usage.json'
    $fixtureMixed = Join-Path $dataDir 'usage-mixed.json'
    $fixtureMissing = Join-Path $dataDir 'definitely-missing.json'

    # Two valid records. Token math is pinned by the assertions below:
    #   record 1: 100+20+5+50 = 175 include / 150 exclude
    #   record 2: 200+0+0+80  = 280 include / 280 exclude
    #   totals:   455 include / 430 exclude
    $validJson = @'
[
  {
    "recordKey": "smoke-record-1",
    "groupKey": null,
    "resetKey": null,
    "kind": "delta",
    "occurredAt": "2026-11-02T01:00:00Z",
    "tool": "codex",
    "model": "gpt-5.2",
    "input": "100",
    "cacheRead": "20",
    "cacheWrite": "5",
    "output": "50",
    "adapterVersion": "smoke-v1",
    "sourceType": "fixture"
  },
  {
    "recordKey": "smoke-record-2",
    "groupKey": null,
    "resetKey": null,
    "kind": "delta",
    "occurredAt": "2026-11-02T02:00:00Z",
    "tool": "claude-code",
    "model": null,
    "input": "200",
    "cacheRead": "0",
    "cacheWrite": "0",
    "output": "80",
    "adapterVersion": "smoke-v1",
    "sourceType": "fixture"
  }
]
'@
    Write-SmokeAsciiFile -Path $fixtureValid -Content $validJson

    # One valid record plus one invalid record (kind must be delta|cumulative).
    $mixedJson = @'
[
  {
    "recordKey": "smoke-record-3",
    "groupKey": null,
    "resetKey": null,
    "kind": "delta",
    "occurredAt": "2026-11-02T03:00:00Z",
    "tool": "codex",
    "model": null,
    "input": "10",
    "cacheRead": "0",
    "cacheWrite": "0",
    "output": "4",
    "adapterVersion": "smoke-v1",
    "sourceType": "fixture"
  },
  {
    "recordKey": "smoke-record-4",
    "groupKey": null,
    "resetKey": null,
    "kind": "bogus",
    "occurredAt": "2026-11-02T04:00:00Z",
    "tool": "codex",
    "model": null,
    "input": "10",
    "cacheRead": "0",
    "cacheWrite": "0",
    "output": "4",
    "adapterVersion": "smoke-v1",
    "sourceType": "fixture"
  }
]
'@
    Write-SmokeAsciiFile -Path $fixtureMixed -Content $mixedJson

    # --- build the real collector ------------------------------------------
    $exePath = Join-Path $binDir 'toktrail.exe'
    Push-Location -LiteralPath $RepoRoot
    $script:LocationPushed = $true
    [void](Invoke-SmokeNative -Label 'build collector (go build ./cmd/toktrail)' -ExePath $goExePath -Arguments @('build', '-o', $exePath, './cmd/toktrail'))
    Assert-SmokeTrue -Condition (Test-Path -LiteralPath $exePath -PathType Leaf) -Message ("built executable not found at: " + $exePath)
    Write-SmokeLog ("built executable: " + $exePath)

    # --- version / help ------------------------------------------------------
    $versionOut = Invoke-SmokeNative -Label 'version' -ExePath $exePath -Arguments @('version')
    Assert-SmokeMatch -Text $versionOut -Pattern '(?m)^toktrail \S+$' -Message 'version must print one "toktrail <version>" line'

    $helpOut = Invoke-SmokeNative -Label 'help' -ExePath $exePath -Arguments @('help')
    Assert-SmokeMatch -Text $helpOut -Pattern 'Commands:' -Message 'help must list the command surface'
    Assert-SmokeMatch -Text $helpOut -Pattern 'scan' -Message 'help must mention scan'
    Assert-SmokeMatch -Text $helpOut -Pattern 'export' -Message 'help must mention export'

    # --- negative: unknown command exits 2 ----------------------------------
    [void](Invoke-SmokeNative -Label 'unknown command (expect exit 2)' -ExePath $exePath -Arguments @('definitely-not-a-command') -ExpectedExitCode 2)
    Assert-SmokeMatch -Text $script:LastNativeOutput -Pattern 'unknown command' -Message 'unknown command must be reported'

    # --- scan: valid fixture --------------------------------------------------
    # Every stateful subcommand gets an explicit --state-dir into the isolated
    # tree (TOKTRAIL_HOME points there as well; both are checked here).
    $scanOut = Invoke-SmokeNative -Label 'scan valid fixture' -ExePath $exePath -Arguments @('scan', '--source', 'usage-json', '--input', $fixtureValid, '--state-dir', $stateDir)
    Assert-SmokeMatch -Text $scanOut -Pattern '(?m)^source=usage-json records=2 valid=2 invalid=0$' -Message 'scan summary line'
    Assert-SmokeMatch -Text $scanOut -Pattern '(?m)^knownIncludeRecords=2 tokensInclude=455 knownExcludeRecords=2 tokensExclude=430$' -Message 'scan token totals (100+20+5+50 + 200+0+0+80)'
    Assert-SmokeMatch -Text $scanOut -Pattern '(?m)^range=2026-11-02T01:00:00Z\.\.2026-11-02T02:00:00Z$' -Message 'scan occurred-at range'
    Assert-SmokeMatch -Text $scanOut -Pattern '(?m)^tool\[claude-code\]=1$' -Message 'scan claude-code tool count'
    Assert-SmokeMatch -Text $scanOut -Pattern '(?m)^tool\[codex\]=1$' -Message 'scan codex tool count'

    # --- scan: fixture with one invalid record -------------------------------
    $scanMixedOut = Invoke-SmokeNative -Label 'scan mixed fixture (1 valid, 1 invalid)' -ExePath $exePath -Arguments @('scan', '--source', 'usage-json', '--input', $fixtureMixed, '--state-dir', $stateDir)
    Assert-SmokeMatch -Text $scanMixedOut -Pattern '(?m)^source=usage-json records=2 valid=1 invalid=1$' -Message 'mixed scan must count the invalid record'
    Assert-SmokeMatch -Text $scanMixedOut -Pattern '(?m)^tool\[codex\]=2$' -Message 'mixed scan tool count'

    # --- preview ---------------------------------------------------------------
    $previewOut = Invoke-SmokeNative -Label 'preview valid fixture' -ExePath $exePath -Arguments @('preview', '--source', 'usage-json', '--input', $fixtureValid, '--state-dir', $stateDir)
    Assert-SmokeMatch -Text $previewOut -Pattern '(?m)^0 smoke-record-1 tool=codex kind=delta occurredAt=2026-11-02T01:00:00Z include=175 exclude=150 ok$' -Message 'preview line for smoke-record-1'
    Assert-SmokeMatch -Text $previewOut -Pattern '(?m)^1 smoke-record-2 tool=claude-code kind=delta occurredAt=2026-11-02T02:00:00Z include=280 exclude=280 ok$' -Message 'preview line for smoke-record-2'

    # --- negative: scan a missing input exits 1 -------------------------------
    [void](Invoke-SmokeNative -Label 'scan missing input (expect exit 1)' -ExePath $exePath -Arguments @('scan', '--source', 'usage-json', '--input', $fixtureMissing, '--state-dir', $stateDir) -ExpectedExitCode 1)
    Assert-SmokeMatch -Text $script:LastNativeOutput -Pattern 'scan failed' -Message 'missing input must fail with a scan failure'

    # --- negative: export with an invalid record is rejected whole ------------
    [void](Invoke-SmokeNative -Label 'export invalid fixture (expect exit 1)' -ExePath $exePath -Arguments @('export', '--source', 'usage-json', '--input', $fixtureMixed, '--out', (Join-Path $outDir 'batch-mixed.json'), '--batch', 'smoke-batch-invalid', '--state-dir', $stateDir) -ExpectedExitCode 1)
    Assert-SmokeMatch -Text $script:LastNativeOutput -Pattern 'export failed' -Message 'invalid fixture must fail the export'
    Assert-SmokeMatch -Text $script:LastNativeOutput -Pattern 'invalid kind' -Message 'invalid record must be reported as an invalid kind'

    # --- export: valid fixture --------------------------------------------------
    $batchFile = Join-Path $outDir 'batch.json'
    $exportOut = Invoke-SmokeNative -Label 'export valid fixture' -ExePath $exePath -Arguments @('export', '--source', 'usage-json', '--input', $fixtureValid, '--out', $batchFile, '--batch', 'smoke-batch-1', '--state-dir', $stateDir)
    Assert-SmokeMatch -Text $exportOut -Pattern '(?m)^exported batch smoke-batch-1 records=2 file=' -Message 'export must report the batch and record count'
    Assert-SmokeMatch -Text $exportOut -Pattern '(?m)^outbox=.+ status=pending$' -Message 'export must register a pending outbox batch'
    Assert-SmokeMatch -Text $exportOut -Pattern '(?m)^cursor=.+ batch=smoke-batch-1$' -Message 'export must advance the cursor'

    # Verify the artifacts on disk (filesystem checks are encoding-independent).
    Assert-SmokeTrue -Condition (Test-Path -LiteralPath $batchFile -PathType Leaf) -Message ("export batch file missing: " + $batchFile)
    $outboxFile = Join-Path $stateDir 'outbox.json'
    $cursorFile = Join-Path $stateDir 'adapter-cursors.json'
    Assert-SmokeTrue -Condition (Test-Path -LiteralPath $outboxFile -PathType Leaf) -Message ("outbox file missing: " + $outboxFile)
    Assert-SmokeTrue -Condition (Test-Path -LiteralPath $cursorFile -PathType Leaf) -Message ("cursor file missing: " + $cursorFile)

    $batchJson = Get-Content -Raw -LiteralPath $batchFile | ConvertFrom-Json
    Assert-SmokeTrue -Condition ($batchJson.batchId -eq 'smoke-batch-1') -Message 'batch file batchId'
    Assert-SmokeTrue -Condition (@($batchJson.records).Count -eq 2) -Message 'batch file must carry 2 records'
    Assert-SmokeTrue -Condition ($batchJson.records[0].recordKey -eq 'smoke-record-1') -Message 'batch record 1 recordKey'
    Assert-SmokeTrue -Condition ($batchJson.records[0].input -eq '100') -Message 'batch record 1 input'
    Assert-SmokeTrue -Condition ($batchJson.records[0].cacheRead -eq '20') -Message 'batch record 1 cacheRead'
    Assert-SmokeTrue -Condition ($batchJson.records[1].output -eq '80') -Message 'batch record 2 output'

    $outboxJson = Get-Content -Raw -LiteralPath $outboxFile | ConvertFrom-Json
    Assert-SmokeTrue -Condition (@($outboxJson.batches).Count -eq 1) -Message 'outbox must hold exactly the 1 batch (the rejected export must not have registered one)'
    Assert-SmokeTrue -Condition ($outboxJson.batches[0].batchId -eq 'smoke-batch-1') -Message 'outbox batch id'
    Assert-SmokeTrue -Condition ($outboxJson.batches[0].status -eq 'pending') -Message 'outbox batch status'
    Assert-SmokeTrue -Condition ($outboxJson.batches[0].recordCount -eq 2) -Message 'outbox batch record count'

    # --- privacy (local-only report) --------------------------------------------
    $privacyOut = Invoke-SmokeNative -Label 'privacy report' -ExePath $exePath -Arguments @('privacy', '--source', 'usage-json', '--input', $fixtureValid, '--state-dir', $stateDir)
    Assert-SmokeMatch -Text $privacyOut -Pattern '(?m)^records=2 valid=2 invalid=0 quarantined=0$' -Message 'privacy record summary'
    Assert-SmokeMatch -Text $privacyOut -Pattern '(?m)^uploadSafeRecords=2 tokensInclude=455 tokensExclude=430$' -Message 'privacy upload-safe totals'
    Assert-SmokeMatch -Text $privacyOut -Pattern '(?m)^outboxPending=1 outboxPendingRecords=2$' -Message 'privacy must see the 1 pending outbox batch'
    Assert-SmokeMatch -Text $privacyOut -Pattern '(?m)^note=privacy is local-only; no network access was performed$' -Message 'privacy must declare it stayed offline'

    # --- sources enable / list ----------------------------------------------------
    $enableOut = Invoke-SmokeNative -Label 'sources enable (grant the fixture)' -ExePath $exePath -Arguments @('sources', 'enable', '--source', 'usage-json', '--input', $fixtureValid, '--state-dir', $stateDir)
    Assert-SmokeMatch -Text $enableOut -Pattern 'enabled grant usage-json' -Message 'sources enable must confirm the grant'

    $sourcesListOut = Invoke-SmokeNative -Label 'sources list' -ExePath $exePath -Arguments @('sources', 'list', '--state-dir', $stateDir)
    Assert-SmokeMatch -Text $sourcesListOut -Pattern '(?m)^grant usage-json .+ enabled$' -Message 'sources list must show the enabled grant'
    $grantsFile = Join-Path $stateDir 'grants.json'
    Assert-SmokeTrue -Condition (Test-Path -LiteralPath $grantsFile -PathType Leaf) -Message ("grants file missing: " + $grantsFile)

    # --- doctor (offline; no --check-server) ---------------------------------------
    $doctorOut = Invoke-SmokeNative -Label 'doctor (offline)' -ExePath $exePath -Arguments @('doctor', '--state-dir', $stateDir)
    Assert-SmokeMatch -Text $doctorOut -Pattern '(?m)^ok outbox 1 pending batch\(es\), 2 record\(s\) awaiting upload$' -Message 'doctor must see the pending outbox batch'
    Assert-SmokeMatch -Text $doctorOut -Pattern 'server check skipped' -Message 'doctor must skip the server check (offline)'
    Assert-SmokeMatch -Text $doctorOut -Pattern '(?m)^warn scheduler no scheduled task for this state directory' -Message 'doctor must find no scheduled task in the isolated state dir'
    Assert-SmokeMatch -Text $doctorOut -Pattern '(?m)^ok grants 1 enabled source grant\(s\)$' -Message 'doctor must see the enabled grant'

    # --- optional: non-ASCII path echo ---------------------------------------------
    # The exe must echo the isolated non-ASCII state path verbatim. This needs
    # UTF-8 console decoding; when that was unavailable, the filesystem checks
    # above still prove the non-ASCII paths were used.
    if ($script:UnicodeOutputReliable) {
        Assert-SmokeMatch -Text $sourcesListOut -Pattern ('(?m)^state=' + [regex]::Escape($grantsFile) + '$') -Message 'sources list must echo the isolated non-ASCII state path'
    } else {
        Write-SmokeLog 'skipping non-ASCII output echo assertion (console encoding is not UTF-8)'
    }

    Write-SmokeLog ('SMOKE PASSED: ' + $script:VerifiedSteps + ' verified checks; collector CLI is functional on this platform')
} catch {
    $script:ExitCode = 1
    Write-SmokeLog ('SMOKE FAILED at step ''' + $script:CurrentStep + ''': ' + $_.Exception.Message)
    if (-not [string]::IsNullOrEmpty($script:LastNativeOutput)) {
        Write-SmokeLog 'last native command output was:'
        foreach ($line in ($script:LastNativeOutput -split "`n")) { Write-SmokeLog ('  | ' + $line) }
    }
} finally {
    Restore-SmokeEnv
    if ($script:LocationPushed) {
        Pop-Location
        $script:LocationPushed = $false
    }
    if ($KeepTemp) {
        if ($null -ne $script:TempRoot) { Write-SmokeLog ('temp root kept for inspection: ' + $script:TempRoot) }
    } else {
        $script:CurrentStep = 'cleanup temp root'
        try {
            Remove-SmokeTempRoot
            Write-SmokeLog 'temp root removed'
        } catch {
            $script:ExitCode = 1
            Write-SmokeLog ('CLEANUP FAILED: ' + $_.Exception.Message)
        }
    }
}

exit $script:ExitCode
