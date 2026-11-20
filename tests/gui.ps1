[CmdletBinding()]
param(
    [string]$Cli = '',
    [ValidateSet('x64','x86')][string]$Architecture = 'x64',
    [switch]$EnableAnnotations
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'cli-process.ps1')
$workspace = Split-Path -Parent $PSScriptRoot
if (!$Cli) { $Cli = Join-Path $workspace 'out/windows-x64/Release/x64dbgsql.exe' }
$program = if ($Architecture -eq 'x64') { 'x64' } else { 'x32' }
$extension = if ($Architecture -eq 'x64') { 'dp64' } else { 'dp32' }
$outputs = Join-Path $workspace "out/windows-$Architecture/Release"
$debugger = Join-Path $workspace ".deps/debugger/release/$program/${program}dbg.exe"
$directory = Join-Path ([IO.Path]::GetTempPath()) ('x64dbgSQL GUI ' + [Guid]::NewGuid().ToString('n'))
New-Item -Path $directory -ItemType Directory | Out-Null
$plugin = Join-Path $directory "x64dbgsql.$extension"
Copy-Item -LiteralPath (Join-Path $outputs "x64dbgsql.$extension") -Destination $plugin
$fixture = Join-Path $outputs 'x64dbgsql_fixture.exe'
$start = New-Object Diagnostics.ProcessStartInfo
$start.FileName = $debugger
$start.Arguments = Join-NativeArguments '-userdir' $directory '-plugin' $plugin $fixture
$start.WorkingDirectory = Split-Path -Parent $debugger
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.WindowStyle = 'Hidden'
$start.EnvironmentVariables.Remove('X64DBGSQL_ENABLE_ANNOTATIONS')
if ($EnableAnnotations) {
    $start.EnvironmentVariables['X64DBGSQL_ENABLE_ANNOTATIONS'] = '1'
}
$process = [Diagnostics.Process]::Start($start)

function Complete-Annotation($response) {
    if (!$response.ok) { throw "Annotation request failed: $($response | ConvertTo-Json -Compress -Depth 8)" }
    for ($attempt = 0; $attempt -lt 80; ++$attempt) {
        $result = Invoke-Cli action status $response.action_id --session $session.session
        if ($result.ok -and $result.status -eq 'done' -and $result.audit_recorded) { return }
        if (!$result.ok -or $result.status -ne 'accepted') {
            throw "Annotation action failed: $($result | ConvertTo-Json -Compress -Depth 8)"
        }
        Start-Sleep -Milliseconds 60
    }
    throw 'Annotation action timed out'
}

try {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    do {
        if ($process.HasExited) { throw 'GUI debugger exited before publishing a session' }
        $session = (Invoke-Cli sessions).sessions | Where-Object { $_.pid -eq $process.Id }
        if ($session) {
            $status = Invoke-Cli status --session $session.session
            if ($status.state -eq 'paused' -and $status.debuggee_pid -ne 0) { break }
        }
        Start-Sleep -Milliseconds 125
    } while ($watch.Elapsed.TotalSeconds -lt 18)
    if (!$session -or $status.state -ne 'paused') { throw 'GUI did not reach a session with a paused fixture' }
    $reply = Invoke-Cli query --session $session.session --json -q 'SELECT ip,tid,module,rva FROM stop_context'
    if (!$reply.ok -or $reply.row_count -ne 1) { throw "GUI stop query failed: $($reply | ConvertTo-Json -Compress -Depth 8)" }
    $control = Invoke-Cli control run --session $session.session --reason 'GUI permission test'
    if ($control.ok -or $control.error.code -ne 'E_PERM') { throw 'GUI must reject fixture-only control' }
    if (!$EnableAnnotations) {
        $annotation = Invoke-Cli annotation set comment 0x1000 'permission test' --session $session.session --reason 'GUI permission test'
        if ($status.annotation_enabled -or $annotation.ok -or $annotation.error.code -ne 'E_PERM') {
            throw 'GUI annotations must begin disabled without startup opt-in'
        }
        "GUI $($Architecture): auto-connected for queries and enforced default action permissions"
    } else {
        if (!$status.annotation_enabled) { throw 'Explicit startup opt-in did not enable GUI annotations' }
        $image = Invoke-Cli query --session $session.session --json -q "SELECT printf('0x%X',entry) FROM modules WHERE name='x64dbgsql_fixture.exe'"
        if (!$image.ok -or $image.row_count -ne 1) { throw 'Could not resolve fixture entry' }
        $address = $image.rows[0][0]
        $options = @('--session', $session.session, '--reason', 'GUI startup opt-in test')
        foreach ($kind in 'comment', 'label', 'bookmark') {
            $text = if ($kind -eq 'comment') { 'GUI test "annotation"' } else { 'gui_test_label' }
            $body = if ($kind -eq 'bookmark') { ,@() } else { ,@($text) }
            $column = if ($kind -eq 'bookmark') { 'manual' } else { 'text' }
            $sql = "SELECT $column FROM $($kind)s WHERE addr=$address AND manual=1"
            Complete-Annotation (Invoke-Cli annotation set $kind $address @body @options)
            $saved = Invoke-Cli query --json --session $session.session -q $sql
            if (!$saved.ok -or $saved.row_count -ne 1) { throw "Could not query $kind" }
            $expected = if ($kind -eq 'bookmark') { '1' } else { $text }
            $actual = if ($kind -eq 'bookmark') { $saved.rows[0][0].int64 } else { $saved.rows[0][0] }
            if ($actual -cne $expected) { throw "Could not read back $kind" }
            Complete-Annotation (Invoke-Cli annotation remove $kind $address @options)
            $deleted = Invoke-Cli query --json --session $session.session -q $sql
            if (!$deleted.ok -or $deleted.row_count -ne 0) { throw "Could not verify removed $kind" }
        }
        "GUI $($Architecture): startup opt-in, comment/label/bookmark round trips and audit passed"
    }
} finally {
    if (!$process.HasExited) {
        $null = $process.CloseMainWindow()
        if (!$process.WaitForExit(3500)) { $process.Kill(); $process.WaitForExit() }
    }
    $process.Dispose()
}
