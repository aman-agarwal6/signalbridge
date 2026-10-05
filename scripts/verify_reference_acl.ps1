# Native Windows regression: one freshly owned synthetic fixture scope only.
# No Docker, credentials, host policy, elevation or ownership changes.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$scriptPath = Join-Path $workspace 'integrations\enterprise\reference-private-acl.ps1'
$testParent = Join-Path $workspace 'var\tests'
$run = [Guid]::NewGuid().ToString('N')
$testWorkspace = Join-Path $testParent ('native-acl-' + $run)
$runPath = Join-Path $testWorkspace ('var\enterprise\runs\' + $run)
$checks = [Collections.Generic.List[string]]::new()
$started = [DateTime]::UtcNow.ToString('o')
$powershellPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$scopeCreated = $false
$childExitedVerified = $true
$passed = $false
$fixturePhase = 1
$failurePhase = 0
$cleanupVerified = $true
$temporaryWorkspaceRemoved = $false
$lastHelperDiagnostic = $null

function Assert-WorkspaceAncestors([string]$Parent) {
    # Require an existing ordinary parent; never create through a junction.
    $ancestor = Get-Item -LiteralPath $Parent -Force
    while ($null -ne $ancestor) {
        if ($ancestor -isnot [IO.DirectoryInfo] -or
            ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Redirected fixture ancestor refused.'
        }
        if ($ancestor.FullName.TrimEnd('\') -ieq $workspace.TrimEnd('\')) { return }
        $ancestor = $ancestor.Parent
    }
    throw 'Fixture ancestor escaped its workspace.'
}

function Read-BoundedOutput([IO.Stream]$Stream, [byte[]]$Buffer, $ReadTask) {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $used = 0
    while ($true) {
        $remaining = 1000 - [int]$clock.ElapsedMilliseconds
        if ($remaining -le 0 -or -not $ReadTask.Wait($remaining)) { throw 'Fixture output drain exceeded its budget.' }
        $read = $ReadTask.Result
        if ($read -eq 0) { break }
        $used += $read
        if ($used -gt 1024) { throw 'Fixture output exceeded its byte limit.' }
        $ReadTask = $Stream.ReadAsync($Buffer, $used, $Buffer.Length - $used)
    }
    # Only the helper's ASCII JSON protocol is expected; invalid UTF-8 is denied.
    return [Text.UTF8Encoding]::new($false, $true).GetString($Buffer, 0, $used)
}

function Read-FixedDiagnostic([string]$Raw, [string]$ExpectedMode) {
    if ([Text.Encoding]::UTF8.GetByteCount($Raw) -gt 1024 -or -not $Raw.Trim()) { return $null }
    if ($ExpectedMode -cnotin @('SecureEmpty', 'Verify')) { return $null }
    # Windows PowerShell 5.1 can discard duplicate JSON keys. Require the
    # helper's ordered compact wire form before parsing any diagnostic.
    $prefix = '\A\{"kind":"signalbridge-private-acl-failure","mode":"' + $ExpectedMode
    $wire = $prefix +
        '","phase":(?:[1-9]|1[0-7]),"checked_count":(?:0|[1-9][0-9]{0,3})\}(?:\r?\n)?\z'
    $numericWire = $prefix +
        '","phase":8,"checked_count":(?:0|[1-9][0-9]{0,3}),"api_hresult":(?:null|0|-?[1-9][0-9]{0,9})\}(?:\r?\n)?\z'
    if ($Raw -cnotmatch $wire -and $Raw -cnotmatch $numericWire) { return $null }
    try {
        $value = $Raw | ConvertFrom-Json
        $names = @($value.PSObject.Properties.Name | Sort-Object)
        $hasHResult = $names -ccontains 'api_hresult'
        $fields = if ($hasHResult) { 'api_hresult,checked_count,kind,mode,phase' } else { 'checked_count,kind,mode,phase' }
        if (($names -join ',') -cne $fields -or
            $value.kind -cne 'signalbridge-private-acl-failure' -or $value.mode -cne $ExpectedMode -or
            $value.phase -isnot [int] -or $value.phase -lt 1 -or $value.phase -gt 17 -or
            $value.checked_count -isnot [int] -or $value.checked_count -lt 0 -or $value.checked_count -gt 2501) {
            return $null
        }
        if ($hasHResult -and ($value.phase -ne 8 -or
            ($null -ne $value.api_hresult -and $value.api_hresult -isnot [int]))) { return $null }
        $result = [ordered]@{
            kind = 'signalbridge-private-acl-failure'
            mode = $ExpectedMode
            phase = $value.phase
            checked_count = $value.checked_count
        }
        if ($hasHResult) { $result['api_hresult'] = $value.api_hresult }
        return $result
    } catch { return $null }
}

function Assert-AclResult([string]$Mode, [bool]$ExpectedSuccess, [int]$ExpectedFailurePhase = 0) {
    $script:fixturePhase = 20
    $script:lastHelperDiagnostic = $null
    if ($Mode -cnotin @('SecureEmpty', 'Verify') -or $scriptPath -match '["\r\n]' -or
        $testWorkspace -match '["\r\n]') { throw 'Invalid fixed fixture invocation.' }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $powershellPath
    # Fixed mode/hex run and quote-free absolute paths; no shell interpretation.
    $start.Arguments = '-NoLogo -NoProfile -NonInteractive -File "' + $scriptPath +
        '" -Workspace "' + $testWorkspace + '" -Run ' + $run + ' -Mode ' + $Mode
    $start.WorkingDirectory = $workspace
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    # Match enterprise_reference_verify.clean_environment exactly. In particular,
    # preserve OS ProgramData/SystemDrive without inheriting unrelated variables.
    $start.EnvironmentVariables.Clear()
    foreach ($name in @('SYSTEMROOT', 'WINDIR', 'PATH', 'TEMP', 'TMP', 'USERPROFILE',
        'LOCALAPPDATA', 'APPDATA', 'PROGRAMDATA', 'SYSTEMDRIVE')) {
        $value = [Environment]::GetEnvironmentVariable($name, 'Process')
        if ($null -ne $value) { $start.EnvironmentVariables[$name] = $value }
    }
    $start.EnvironmentVariables['PYTHONDONTWRITEBYTECODE'] = '1'
    $start.EnvironmentVariables['PYTHONUTF8'] = '1'
    $start.EnvironmentVariables['COMPOSE_DISABLE_ENV_FILE'] = '1'
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw 'Fixed fixture child did not start.' }
        $script:childExitedVerified = $false
        $stdoutBuffer = [byte[]]::new(1025)
        $stderrBuffer = [byte[]]::new(1025)
        $stdoutStream = $process.StandardOutput.BaseStream
        $stderrStream = $process.StandardError.BaseStream
        $stdout = $stdoutStream.ReadAsync($stdoutBuffer, 0, $stdoutBuffer.Length)
        $stderr = $stderrStream.ReadAsync($stderrBuffer, 0, $stderrBuffer.Length)
        $script:fixturePhase = 21
        if (-not $process.WaitForExit(30000)) {
            throw 'Fixed fixture child exceeded its time budget.'
        }
        $script:childExitedVerified = $true
        $script:fixturePhase = 22
        $output = Read-BoundedOutput $stdoutStream $stdoutBuffer $stdout
        $errorOutput = Read-BoundedOutput $stderrStream $stderrBuffer $stderr
        $script:fixturePhase = 23
        if ([Text.Encoding]::UTF8.GetByteCount($output) -gt 1024 -or
            [Text.Encoding]::UTF8.GetByteCount($errorOutput) -gt 1024) {
            throw 'Fixed fixture output exceeded its retained limit.'
        }
        $script:lastHelperDiagnostic = Read-FixedDiagnostic $errorOutput $Mode
        $script:fixturePhase = 24
        if (($process.ExitCode -eq 0) -ne $ExpectedSuccess) { throw 'Native ACL regression failed.' }
        if ($ExpectedSuccess) {
            if ($errorOutput.Length -ne 0) { throw 'Native ACL success emitted error-channel data.' }
            $successWire = '\A\{(?:"private_acl_verified":true,"inherited_public_access_removed":true|' +
                '"inherited_public_access_removed":true,"private_acl_verified":true)\}(?:\r?\n)?\z'
            if ($output -cnotmatch $successWire) { throw 'Native ACL success wire form changed.' }
            $result = $output | ConvertFrom-Json
            $names = @($result.PSObject.Properties.Name | Sort-Object)
            if ($names.Count -ne 2 -or $names[0] -cne 'inherited_public_access_removed' -or
                $names[1] -cne 'private_acl_verified' -or $result.private_acl_verified -isnot [bool] -or
                $result.inherited_public_access_removed -isnot [bool] -or
                -not $result.private_acl_verified -or -not $result.inherited_public_access_removed) {
                throw 'Native ACL receipt failed.'
            }
        } elseif ($process.ExitCode -ne 1 -or $output.Length -ne 0 -or $null -eq $script:lastHelperDiagnostic -or
            $script:lastHelperDiagnostic.phase -ne $ExpectedFailurePhase) {
            throw 'Native ACL denial did not match the fixed protocol.'
        }
    } finally {
        # Do not delete the fixture while an owned child might still be active.
        if (-not $script:childExitedVerified) {
            try {
                # This object belongs only to the child just started here.
                $process.Kill()
                $script:childExitedVerified = $process.WaitForExit(5000)
            } catch { }
        }
        $process.Dispose()
    }
}

try {
    Assert-WorkspaceAncestors $testParent
    if (Test-Path -LiteralPath $testWorkspace) { throw 'Fresh test workspace already exists.' }
    # No -Force: a collision must fail without claiming or deleting its scope.
    New-Item -ItemType Directory -Path $testWorkspace | Out-Null
    $scopeCreated = $true
    [IO.Directory]::CreateDirectory($runPath) | Out-Null
    $originalOwner = (Get-Acl -LiteralPath $runPath).GetOwner([Security.Principal.SecurityIdentifier]).Value
    Assert-AclResult 'Verify' $false 13
    $checks.Add('Inherited permissions rejected before protection')
    Assert-AclResult 'SecureEmpty' $true
    $checks.Add('Fresh folder secured through raw DirectoryInfo ancestors')
    if ((Get-Acl -LiteralPath $runPath).GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $originalOwner) {
        throw 'Native ACL protection changed ownership.'
    }
    $checks.Add('DACL-only protection retained the original current-user owner')
    $accessSection = [Security.AccessControl.AccessControlSections]::Access
    $trustedDescriptor = (Get-Acl -LiteralPath $runPath).GetSecurityDescriptorSddlForm($accessSection)
    $trustedAcl = [Security.AccessControl.DirectorySecurity]::new()
    $trustedAcl.SetSecurityDescriptorSddlForm($trustedDescriptor, $accessSection)
    $childPath = Join-Path $runPath 'evidence'
    New-Item -ItemType Directory -Path $childPath | Out-Null
    [IO.File]::WriteAllText((Join-Path $childPath 'synthetic.txt'), 'Synthetic ACL test only.')
    Assert-AclResult 'Verify' $true
    $checks.Add('Nested folder and file inherited only approved access')
    Assert-AclResult 'SecureEmpty' $false 6
    $checks.Add('Nonempty folder cannot be reinitialized')
    if ((Get-Acl -LiteralPath $runPath).GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $originalOwner) {
        throw 'Native ACL denial changed ownership.'
    }
    $checks.Add('Nonempty denial retained the original owner')
    $changedAcl = [Security.AccessControl.DirectorySecurity]::new()
    $changedAcl.SetSecurityDescriptorSddlForm($trustedDescriptor, $accessSection)
    $everyone = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
    $changedAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $everyone, [Security.AccessControl.FileSystemRights]::Read,
        [Security.AccessControl.AccessControlType]::Allow
    ))
    [IO.Directory]::SetAccessControl($runPath, $changedAcl)
    Assert-AclResult 'Verify' $false 14
    $checks.Add('Unexpected public read permission rejected')
    [IO.Directory]::SetAccessControl($runPath, $trustedAcl)
    Assert-AclResult 'Verify' $true
    $checks.Add('Restored private permissions verified')
    $passed = $true
} catch {
    $failurePhase = $fixturePhase
} finally {
    if ($scopeCreated) {
        try {
            if (-not $childExitedVerified) { throw 'Fixture child termination was not verified.' }
            Assert-WorkspaceAncestors $testParent
            $resolved = (Resolve-Path -LiteralPath $testWorkspace).ProviderPath
            if ($resolved -ne $testWorkspace -or
                -not $resolved.StartsWith($testParent + '\', [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Test cleanup escaped its scope.'
            }
            $pending = [Collections.Generic.Queue[string]]::new()
            $pending.Enqueue($resolved)
            $cleanupCount = 0
            $cleanupClock = [Diagnostics.Stopwatch]::StartNew()
            while ($pending.Count) {
                if (++$cleanupCount -gt 2500 -or $cleanupClock.ElapsedMilliseconds -gt 5000) {
                    throw 'Fixture cleanup exceeded its traversal budget.'
                }
                $item = Get-Item -LiteralPath $pending.Dequeue() -Force
                if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Redirected test cleanup refused.' }
                if ($item -is [IO.DirectoryInfo]) {
                    foreach ($child in Get-ChildItem -LiteralPath $item.FullName -Force) { $pending.Enqueue($child.FullName) }
                }
            }
            Remove-Item -LiteralPath $resolved -Recurse -Force
            $temporaryWorkspaceRemoved = -not (Test-Path -LiteralPath $testWorkspace)
            if (-not $temporaryWorkspaceRemoved) { throw 'Fixture cleanup was not verified.' }
        } catch {
            $cleanupVerified = $false
            $passed = $false
            if (-not $failurePhase) { $failurePhase = 30 }
        }
    }
}
try {
    $receipt = [ordered]@{
        schema_version = 1
        kind = 'signalbridge-native-windows-private-acl-regression'
        started_at = $started
        finished_at = [DateTime]::UtcNow.ToString('o')
        passed = $passed
        checks = @($checks)
        checks_passed = $checks.Count
        acl_script_sha256 = (Get-FileHash -LiteralPath $scriptPath -Algorithm SHA256).Hash.ToLowerInvariant()
        verifier_sha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
        temporary_workspace_removed = $temporaryWorkspaceRemoved
        cleanup_verified = $cleanupVerified
        failure = if ($failurePhase) { [ordered]@{ fixture_phase = $failurePhase; helper = $lastHelperDiagnostic } } else { $null }
        limits = 'Actual Windows fixture permissions only; no source HTTP, database, Docker or native application acceptance.'
    }
    $receiptPath = Join-Path $workspace ('docs\evidence\' + [DateTime]::UtcNow.ToString('yyyyMMdd') + '-native-reference-acl-' + $run + '.json')
    Assert-WorkspaceAncestors (Split-Path -Parent $receiptPath)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($receipt | ConvertTo-Json -Depth 5) + [char]10)
    $stream = [IO.File]::Open($receiptPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
    [ordered]@{ passed = $passed; checks_passed = $checks.Count; cleanup_verified = $cleanupVerified } | ConvertTo-Json -Compress
} catch {
    [Console]::Error.WriteLine('Native ACL fixture receipt could not be retained.')
    exit 1
}
if (-not $passed) { exit 1 }
