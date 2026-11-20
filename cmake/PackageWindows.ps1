param(
    [string]$CMake = 'cmake',
    [string]$Configuration = 'Release',
    [string]$Destination,
    [string]$InnoCompiler
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root 'out'
if (!$Destination) { $Destination = Join-Path $out 'packages' }
$destination = [IO.Path]::GetFullPath($Destination)
$staging = Join-Path $destination ('stage-' + [Guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Path $staging -Force | Out-Null

function Copy-PublicFiles([string[]]$Entries, [string]$Target) {
    foreach ($entry in $Entries) {
        $path = Join-Path $root $entry
        $files = Get-ChildItem -LiteralPath $path -File -Force -Recurse
        foreach ($file in $files) {
            $relative = $file.FullName.Substring($root.Length + 1)
            if ($relative -match '(^|[\\/])(\.git|\.agents|\.claude|\.codex|\.cursor|__pycache__)([\\/]|$)' -or
                $relative -match '^benchmarks[\\/]tokens\.py$' -or
                $file.Name -match '^(AGENTS?\.md|CLAUDE\.md|GEMINI\.md|copilot-instructions\.md|PLAN\.ko\.md|\.env(\..*)?)$' -or
                $file.Extension -in '.pyc', '.pyo', '.log') { continue }
            $targetFile = Join-Path $Target $relative
            New-Item -ItemType Directory -Path (Split-Path -Parent $targetFile) -Force | Out-Null
            Copy-Item -LiteralPath $file.FullName -Destination $targetFile
        }
    }
}

foreach ($arch in @('x64', 'x86')) {
    & $CMake --install (Join-Path $out "windows-$arch") --config $Configuration --prefix $staging --component Runtime
    if ($LASTEXITCODE -ne 0) { throw "Install staging failed for $arch" }
}
$documentation = 'README.md', 'README.ko.md', 'LICENSE', 'docs', 'licenses'
Copy-PublicFiles $documentation $staging

$runtime = Join-Path $destination 'x64dbgsql-windows.zip'
$source = Join-Path $destination 'x64dbgsql-source.zip'
Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $runtime -Force
$sourceStaging = Join-Path $staging 'source'
$sourceEntries = @('.clang-format', '.gitattributes', '.gitignore', '.github/workflows/ci.yml',
    'CMakeLists.txt', 'CMakePresets.json', 'cmake', 'src', 'tests', 'benchmarks', 'installer') + $documentation
Copy-PublicFiles $sourceEntries $sourceStaging
Compress-Archive -Path (Join-Path $sourceStaging '*') -DestinationPath $source -Force

$artifacts = @($runtime, $source)
if ($InnoCompiler) {
    $project = Get-Content -LiteralPath (Join-Path $root 'CMakeLists.txt') -Raw
    if ($project -notmatch 'project\(x64dbgSQL VERSION (\d+\.\d+\.\d+)\s') { throw 'Could not read the project version' }
    $version = $Matches[1]
    & $InnoCompiler "/DVersion=$version" "/DPayload=$staging" "/DDestination=$destination" (Join-Path $root 'installer/x64dbgsql.iss')
    if ($LASTEXITCODE -ne 0) { throw 'Installer compilation failed' }
    $artifacts += Join-Path $destination 'x64dbgsql-setup.exe'
}

$hashes = foreach ($file in $artifacts) {
    (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + (Split-Path -Leaf $file)
}
$hashes | Set-Content -LiteralPath (Join-Path $destination 'SHA256SUMS') -Encoding Ascii
$artifacts
