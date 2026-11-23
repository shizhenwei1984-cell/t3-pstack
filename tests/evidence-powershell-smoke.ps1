$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$env:PYTHONIOENCODING = 'utf-8'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$python = (Get-Command python -CommandType Application).Source
$smoke = Join-Path $PSScriptRoot 'evidence_cli_smoke.py'

function Invoke-EvidenceJson {
    param([int] $ExpectedExit, [string[]] $Arguments)
    $output = & $python @Arguments
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne $ExpectedExit) {
        throw "Expected exit $ExpectedExit, got $exitCode. Output $output"
    }
    ($output -join "`n") | ConvertFrom-Json
}

$fixture = Invoke-EvidenceJson 0 @('-B', $smoke, '--prepare')
try {
    $snapshot = Invoke-EvidenceJson 0 @($fixture.task, 'preserve',
        '--input', $fixture.request, '--store', $fixture.archive)
    if ($snapshot.snapshot.Length -le 260 -or $snapshot.snapshot -like '\\?\*') {
        throw "Expected an ordinary absolute Windows path longer than MAX_PATH: $($snapshot.snapshot)"
    }
    $pin = @('--snapshot', $snapshot.snapshot, '--sha256', $snapshot.snapshot_sha256)
    $check = Invoke-EvidenceJson 0 (@($fixture.task, 'check') + $pin)
    if ($check.archive_integrity -ne 'valid') { throw 'Archive integrity check failed' }
    $render = Invoke-EvidenceJson 0 (@($fixture.task, 'render') + $pin + @('--out', $fixture.render,
        '--document-state', $fixture.state, '--target', $fixture.target, '--document-owner', 'owner'))
    if ($render.proposal.outcome -ne 'proposed' -or [IO.File]::Exists($fixture.target)) {
        throw 'Expected a retained proposal and no new target'
    }
    $binding = @('--state', $fixture.state, '--target', $fixture.target, '--operation-id', 'pwsh')
    $promote = Invoke-EvidenceJson 0 (@($fixture.guard, 'promote') + $binding + @('--decision', 'replace',
        '--proposal', $render.proposal.proposal_id, '--expect-target', 'absent',
        '--expect-draft', $render.proposal.new_generated, '--single-writer'))
    $targetHash = (Get-FileHash -LiteralPath $fixture.target -Algorithm SHA256).Hash
    if ($promote.outcome -ne 'committed' -or $targetHash -ne $promote.desired_target) {
        throw 'Promotion failed to install the reviewed bytes'
    }
    $recover = Invoke-EvidenceJson 0 (@($fixture.guard, 'recover') + $binding)
    if ($recover.outcome -ne 'already_committed') { throw 'Recovery replay failed' }
    $public = Invoke-EvidenceJson 0 @($fixture.task, 'publication',
        '--render', $render.render, '--sha256', $render.render_sha256)
    if ($public.status -ne 'valid') { throw 'Publication did not verify the render' }

    foreach ($bad in @($fixture.bad, $fixture.bom)) {
        $rejection = Invoke-EvidenceJson 1 @($fixture.task, 'preserve',
            '--input', $bad, '--store', $fixture.archive)
        if ($rejection.findings[0].code -ne 'schema_invalid') { throw 'Expected a JSON input error' }
    }
    $ads = Invoke-EvidenceJson 1 @($fixture.task, 'preserve',
        '--input', "$($fixture.request):hidden", '--store', $fixture.archive)
    if ($ads.status -ne 'invalid') { throw 'Expected alternate data stream rejection' }
    $invalid = Invoke-EvidenceJson 1 @($fixture.validation, 'preflight', $fixture.bad)
    if ($invalid.outcome -ne 'invalid') { throw 'Expected a malformed preflight error' }
    $missing = Invoke-EvidenceJson 1 @($fixture.guard, 'recover', '--state', $fixture.state,
        '--target', $fixture.target, '--operation-id', 'missing')
    if ($missing.outcome -ne 'error') { throw 'Expected recovery of an unknown operation to fail' }

    $info = [System.Diagnostics.ProcessStartInfo]::new($python)
    $info.UseShellExecute = $false
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    foreach ($arg in @('-c', 'import sys; print("ready", flush=True); sys.stdin.read()', '証拠 with spaces')) {
        $info.ArgumentList.Add($arg)
    }
    $child = [System.Diagnostics.Process]::Start($info)
    try {
        $ready = $child.StandardOutput.ReadLineAsync()
        if (-not $ready.Wait(10000) -or $ready.Result -ne 'ready') { throw 'Child did not become ready' }
        $observed = Get-CimInstance Win32_Process -Filter "ProcessId = $($child.Id)"
        $candidateHash = (Get-FileHash -LiteralPath $fixture.candidate -Algorithm SHA256).Hash.ToLowerInvariant()
        $contract = @{
            candidate = 'fixed'
            source_mode = 'local'
            files = @(@{ host = $fixture.candidate; visible = $fixture.candidate; sha256 = $candidateHash })
            process = @{
                profile = 'windows'
                pid = $child.Id
                creation_filetime = $child.StartTime.ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture)
                command_line = $observed.CommandLine
            }
        }
        $json = $contract | ConvertTo-Json -Depth 6 -Compress
        [IO.File]::WriteAllText($fixture.preflight, $json, [Text.UTF8Encoding]::new($false))
        $preflight = Invoke-EvidenceJson 1 @($fixture.validation, 'preflight', $fixture.preflight)
        if ($preflight.source_status -ne 'verified' -or $preflight.process_status -ne 'verified' -or
            $preflight.loaded_candidate -ne 'unknown' -or $preflight.outcome -ne 'uncovered') {
            throw "Preflight did not verify the live child: $($preflight | ConvertTo-Json -Compress -Depth 6)"
        }
    }
    finally {
        if (-not $child.HasExited) { $child.Kill() }
        $child.WaitForExit()
        $child.Dispose()
    }
    $exited = Invoke-EvidenceJson 1 @($fixture.validation, 'preflight', $fixture.preflight)
    if ($exited.process_status -ne 'unknown') { throw 'Exited child unexpectedly verified' }
}
finally {
    & $python -B $smoke --verify-and-remove $fixture.root
    if ($LASTEXITCODE -ne 0) { throw 'Staged plugin inventory changed' }
}
Write-Output 'PowerShell staged evidence CLI smoke passed'
