param(
    [Parameter(Mandatory=$true)][string]$Debugger,
    [Parameter(Mandatory=$true)][string]$Plugin,
    [Parameter(Mandatory=$true)][string]$Cli,
    [Parameter(Mandatory=$true)][string]$Fixture,
    [string]$AlternateCli,
    [ValidateRange(0,1000)][int]$Soak = 0
)

$ErrorActionPreference = 'Stop'
$root = Join-Path ([IO.Path]::GetTempPath()) ('x64dbgSQL test ' + [char]0xAC80 + ' ' + [Guid]::NewGuid().ToString('n'))
New-Item -Path $root -ItemType Directory | Out-Null
$stdout = Join-Path $root 'debugger.stdout'
$stderr = Join-Path $root 'debugger.stderr'
$worker = $null
$oldFixture = $env:X64DBGSQL_FIXTURE
if ($AlternateCli -and (Test-Path -LiteralPath $AlternateCli -PathType Leaf)) { $Cli = $AlternateCli }

. (Join-Path $PSScriptRoot 'cli-process.ps1')

function Assert-Result($result, [string]$message) {
    if (!$result.ok) { throw "$message $($result | ConvertTo-Json -Depth 8 -Compress)" }
}

function Wait-For([scriptblock]$test, [string]$message) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while ($watch.Elapsed.TotalSeconds -lt 12) {
        if ($worker.HasExited) { throw 'Debugger exited early' }
        $value = & $test
        if ($value) { return $value }
        Start-Sleep -Milliseconds 80
    }
    throw $message
}

function Invoke-Action([string]$operation, [string]$verb) {
    $response = Invoke-Cli $operation $verb --session $sessionId --reason 'headless integration'
    Assert-Result $response "$operation $verb"
    $actionId = $response.action_id
    $done = Wait-For {
        $action = Invoke-Cli action status $actionId --session $sessionId
        Assert-Result $action 'action status'
        if ($action.status -ne 'accepted') { return $action }
    } 'Action did not finish'
    if ($done.status -ne 'done') { throw ($done | ConvertTo-Json -Compress) }
}

function Test-Mcp([string]$id) {
    $startMcp = New-Object Diagnostics.ProcessStartInfo
    $startMcp.FileName = $Cli
    $startMcp.Arguments = "mcp --session $id"
    $startMcp.UseShellExecute = $false
    $startMcp.CreateNoWindow = $true
    $startMcp.RedirectStandardInput = $true
    $startMcp.RedirectStandardOutput = $true
    $startMcp.RedirectStandardError = $true
    $mcp = [Diagnostics.Process]::Start($startMcp)
    $messages = $mcp.StandardOutput.ReadToEndAsync()
    $errors = $mcp.StandardError.ReadToEndAsync()
    try {
        $mcp.StandardInput.WriteLine('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"ctest","version":"1"}}}')
        $mcp.StandardInput.WriteLine('{"jsonrpc":"2.0","method":"notifications/initialized"}')
        $mcp.StandardInput.WriteLine('{"jsonrpc":"2.0","id":2,"method":"tools/list"}')
        $mcp.StandardInput.WriteLine('{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"x64dbgsql_schema","arguments":{"table":"image_layout"}}}')
        $mcp.StandardInput.WriteLine('{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"control","arguments":{}}}')
        $mcp.StandardInput.WriteLine('{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"x64dbgsql_query","arguments":{"sql":"SELECT * FROM stop_context"}}}')
        $mcp.StandardInput.Close()
        if (!$mcp.WaitForExit(10000)) { throw 'MCP process timed out' }
        $responses = @{}
        foreach ($line in ($messages.Result -split '\r?\n')) {
            if ($line) {
                $response = $line | ConvertFrom-Json
                $responses[[int]$response.id] = $response
            }
        }
        if ($responses[1].result.protocolVersion -ne '2025-11-25' -or $responses[2].result.tools.Count -ne 2) { throw 'MCP initialization or tool list mismatch' }
        if ($responses[3].result.structuredContent.tables[0].name -ne 'image_layout') { throw 'MCP schema query failed' }
        if ($responses[4].error.code -ne -32602) { throw 'MCP exposed an unexpected mutation path' }
        Assert-Result $responses[5].result.structuredContent 'MCP relational query'
    } finally {
        if (!$mcp.HasExited) { $mcp.Kill(); $mcp.WaitForExit() }
        $mcp.Dispose()
    }
}

try {
    $env:X64DBGSQL_FIXTURE = (Resolve-Path -LiteralPath $Fixture).Path
    $arguments = @('-userdir', ('"{0}"' -f $root), '-plugin', ('"{0}"' -f $Plugin), ('"{0}"' -f $Fixture))
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $Debugger
    $start.Arguments = $arguments -join ' '
    $start.WorkingDirectory = Split-Path -Parent $Debugger
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.EnvironmentVariables['X64DBGSQL_ENABLE_ANNOTATIONS'] = '1'
    $worker = [Diagnostics.Process]::Start($start)
    $outStream = $worker.StandardOutput.ReadToEndAsync()
    $errStream = $worker.StandardError.ReadToEndAsync()
    $session = Wait-For {
        (Invoke-Cli sessions).sessions | Where-Object { $_.pid -eq $worker.Id }
    } 'Plugin did not publish a reachable session'
    $sessionId = $session.session
    $status = Wait-For {
        $value = Invoke-Cli status --session $sessionId
        if ($value.state -eq 'paused' -and $value.debuggee_pid -ne 0) { return $value }
    } 'Fixture did not hit its initial pause'
    if (!$status.fixture_profile) { throw 'Fixture profile did not authenticate the image' }
    $denied = Invoke-Cli annotation set comment 0x1000 'test' --session $sessionId --reason 'permission contract'
    if ($denied.ok -or $denied.error.code -ne 'E_PERM') { throw 'Headless annotation permissions were not enforced' }

    $result = Invoke-Cli query --session $sessionId --json -q 'SELECT 1'
    Assert-Result $result 'SQL round trip'
    $result = Invoke-Cli query --session $sessionId --json -q "SELECT module,section,protect FROM image_layout WHERE module LIKE '%fixture.exe' AND section='.text'"
    Assert-Result $result 'PE/runtime join'
    if ($result.row_count -lt 1) { throw 'No fixture .text section was joined' }
    $result = Invoke-Cli query --session $sessionId --json -q 'SELECT s.arch,t.active,r.name FROM session s JOIN threads t ON s.tid=t.tid JOIN registers r ON r.tid=t.tid ORDER BY r.name'
    Assert-Result $result 'Thread/register join'
    if ($result.row_count -lt 8) { throw 'Missing active registers' }
    $result = Invoke-Cli query --session $sessionId --json -q 'SELECT m.bytes FROM session s JOIN memory(s.ip,4) m'
    Assert-Result $result 'Bounded correlated memory'
    if ($result.rows[0][0].blob_hex.Length -ne 8) { throw 'Wrong memory length' }
    $result = Invoke-Cli query --session $sessionId --json -q 'SELECT d.addr=s.ip,d.size,d.text FROM session s JOIN disassembly(s.ip,4) d ORDER BY d.addr'
    Assert-Result $result 'Native instruction decoding'
    if ($result.row_count -ne 4 -or $result.rows[0][0].int64 -ne '1' -or !$result.rows[0][2]) {
        throw 'The decoder did not return four instructions starting at the selected instruction pointer'
    }
    $result = Invoke-Cli query --session $sessionId --json -q 'SELECT count(*) FROM call_stack'
    Assert-Result $result 'Native call stack'
    Test-Mcp $sessionId

    $before = Join-Path $root 'before.json'
    $after = Join-Path $root 'after.json'
    Assert-Result (Invoke-Cli checkpoint capture $before --session $sessionId) 'Capture before'
    Invoke-Action 'breakpoint' 'add'
    Invoke-Action 'control' 'run'
    $null = Wait-For {
        $value = Invoke-Cli status --session $sessionId
        if ($value.state -eq 'paused') { return $value }
    } 'Fixture breakpoint did not pause'
    Invoke-Action 'control' 'step'
    Assert-Result (Invoke-Cli checkpoint capture $after --session $sessionId) 'Capture after'
    $difference = Invoke-Cli checkpoint diff $before $after
    Assert-Result $difference 'Checkpoint diff'
    if ($difference.after_seq -le $difference.before_seq -or !$difference.changes.Count) { throw 'Expected temporal changes' }
    Invoke-Action 'breakpoint' 'remove'
    Invoke-Action 'control' 'run'
    $result = Invoke-Cli query --session $sessionId --json -q 'SELECT * FROM memory(4096,4)'
    if ($result.ok -or $result.error.code -ne 'E_STATE') { throw 'Running-state memory gate failed' }
    Invoke-Action 'control' 'pause'
    $result = Invoke-Cli query --session $sessionId --json -q 'SELECT type FROM event_spans ORDER BY seq DESC LIMIT 15'
    Assert-Result $result 'Event timeline'
    if (!($result.rows | Where-Object { $_[0] -eq 'pause' })) { throw 'Pause event missing' }
    for ($index = 0; $index -lt $Soak; ++$index) {
        Assert-Result (Invoke-Cli query --session $sessionId --json -q 'SELECT count(*) FROM register_context') "Soak query $index"
    }
} catch {
    $problem = $_
} finally {
    $env:X64DBGSQL_FIXTURE = $oldFixture
    if ($worker -and !$worker.HasExited) {
        try { $worker.StandardInput.WriteLine('exit'); $worker.StandardInput.Close() } catch {}
        if (!$worker.WaitForExit(5000)) { $worker.Kill() }
        $worker.WaitForExit()
    }
    if ($worker) {
        [IO.File]::WriteAllText($stdout, $outStream.Result)
        [IO.File]::WriteAllText($stderr, $errStream.Result)
        $worker.Dispose()
    }
}
if ($problem) {
    if (Test-Path -LiteralPath $stdout) { Get-Content -LiteralPath $stdout -Tail 45 }
    if (Test-Path -LiteralPath $stderr) { Get-Content -LiteralPath $stderr -Tail 20 }
    throw $problem
}
if ($sessionId) {
    $registry = (Invoke-Cli doctor).registry
    if (Test-Path -LiteralPath (Join-Path $registry "$sessionId.json")) { throw 'Graceful shutdown left a registry record' }
}
