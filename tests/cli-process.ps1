function Join-NativeArguments {
    # Windows PowerShell lacks ProcessStartInfo.ArgumentList.
    $quoted = foreach ($argument in $args) {
        '"' + ([string]$argument -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
    }
    $quoted -join ' '
}

function Invoke-Cli {
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $Cli
    $start.Arguments = Join-NativeArguments @args
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.StandardOutputEncoding = [Text.Encoding]::UTF8
    $process = [Diagnostics.Process]::Start($start)
    try {
        $output = $process.StandardOutput.ReadToEnd()
        $process.WaitForExit()
        $output | ConvertFrom-Json
    } finally {
        $process.Dispose()
    }
}
