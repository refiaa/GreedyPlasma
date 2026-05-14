param(
    [string]$WindowsSdkVersion = '',
    [string]$Architecture = 'x64'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')
$SourceFile = Join-Path $RepoRoot 'src\Green.cpp'
$ArtifactsDir = Join-Path $RepoRoot 'artifacts'
$OutputExe = Join-Path $ArtifactsDir 'GreedyPlasma.exe'
$ObjectFile = Join-Path $ArtifactsDir 'Green.obj'
$ResponseFile = Join-Path $ArtifactsDir 'build_exe.rsp'

function ConvertTo-ResponseFileArgument {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    if ($Value.IndexOfAny([char[]]" `t`"") -lt 0) {
        return $Value
    }

    return '"' + $Value.Replace('"', '\"') + '"'
}

function Find-VsDevCmd {
    $VsWhere = $null
    $ProgramRoots = @(
        [Environment]::GetEnvironmentVariable('ProgramFiles(x86)'),
        [Environment]::GetEnvironmentVariable('ProgramFiles')
    ) | Where-Object { $_ }

    foreach ($Root in $ProgramRoots) {
        $Candidate = Join-Path $Root 'Microsoft Visual Studio\Installer\vswhere.exe'
        if (Test-Path -LiteralPath $Candidate -PathType Leaf) {
            $VsWhere = $Candidate
            break
        }
    }

    if (-not $VsWhere) {
        return $null
    }

    $InstallPath = & $VsWhere -latest -products '*' -requires 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64' -property installationPath
    if ($LASTEXITCODE -ne 0 -or -not $InstallPath) {
        return $null
    }

    $InstallPath = $InstallPath | Select-Object -First 1
    $DevCmd = Join-Path $InstallPath 'Common7\Tools\VsDevCmd.bat'
    if (Test-Path -LiteralPath $DevCmd -PathType Leaf) {
        return $DevCmd
    }

    return $null
}

function Get-InstalledWindowsSdkVersions {
    $ProgramFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    if (-not $ProgramFilesX86) {
        return @()
    }

    $IncludeRoot = Join-Path $ProgramFilesX86 'Windows Kits\10\Include'
    if (-not (Test-Path -LiteralPath $IncludeRoot -PathType Container)) {
        return @()
    }

    Get-ChildItem -LiteralPath $IncludeRoot -Directory |
        Where-Object {
            $_.Name -match '^\d+\.\d+\.\d+\.\d+$' -and
            (Test-Path -LiteralPath (Join-Path $_.FullName 'um\Windows.h') -PathType Leaf)
        } |
        Sort-Object { [version]$_.Name } -Descending |
        Select-Object -ExpandProperty Name
}

function Select-CompatibleWindowsSdk {
    param(
        [string]$RequestedVersion
    )

    if ($RequestedVersion) {
        return $RequestedVersion
    }

    $Installed = @(Get-InstalledWindowsSdkVersions)
    if ($Installed.Count -eq 0) {
        return ''
    }

    $PreferredMaximum = [version]'10.0.22621.0'
    $Selected = $Installed |
        Where-Object { [version]$_ -le $PreferredMaximum } |
        Select-Object -First 1

    if ($Selected) {
        return $Selected
    }

    return ''
}

if (-not (Test-Path -LiteralPath $SourceFile -PathType Leaf)) {
    throw "Source file not found: $SourceFile"
}

if (-not (Test-Path -LiteralPath $ArtifactsDir -PathType Container)) {
    New-Item -ItemType Directory -Path $ArtifactsDir | Out-Null
}

$CompilerArgs = @(
    '/nologo',
    '/W4',
    '/EHsc',
    '/DUNICODE',
    '/D_UNICODE',
    "/Fo:$ObjectFile",
    "/Fe:$OutputExe",
    $SourceFile,
    '/link',
    'ntdll.lib',
    'advapi32.lib',
    'shell32.lib',
    'user32.lib'
)

$CompilerArgs |
    ForEach-Object { ConvertTo-ResponseFileArgument $_ } |
    Set-Content -LiteralPath $ResponseFile -Encoding ASCII

Write-Host "build=compile-link-only"
Write-Host "source=$SourceFile"
Write-Host "output=$OutputExe"
Write-Host "response=$ResponseFile"
Write-Host "run=disabled"

$DevCmd = Find-VsDevCmd
$SelectedWindowsSdk = Select-CompatibleWindowsSdk -RequestedVersion $WindowsSdkVersion

if ($DevCmd) {
    Write-Host "devcmd=$DevCmd"
    if ($SelectedWindowsSdk) {
        Write-Host "winsdk=$SelectedWindowsSdk"
        $CmdLine = 'call "' + $DevCmd + '" -arch=' + $Architecture + ' -host_arch=' + $Architecture + ' -winsdk=' + $SelectedWindowsSdk + ' >nul && cl.exe "@' + $ResponseFile + '"'
    }
    else {
        Write-Host "winsdk=default"
        $CmdLine = 'call "' + $DevCmd + '" -arch=' + $Architecture + ' -host_arch=' + $Architecture + ' >nul && cl.exe "@' + $ResponseFile + '"'
    }

    & $env:ComSpec /d /s /c $CmdLine
}
else {
    $ClCommand = Get-Command cl.exe -ErrorAction SilentlyContinue
    if (-not $ClCommand) {
        throw 'cl.exe was not found, and Visual Studio Build Tools could not be located. Install Visual Studio Build Tools with the MSVC x64 toolset, or run from an x64 Developer PowerShell.'
    }

    Write-Host "devcmd=not-found"
    Write-Host "winsdk=current-environment"
    & $ClCommand.Source ('@' + $ResponseFile)
}
$BuildExitCode = $LASTEXITCODE

if ($BuildExitCode -ne 0) {
    Write-Error "cl.exe failed with exit code $BuildExitCode"
    exit $BuildExitCode
}

if (-not (Test-Path -LiteralPath $OutputExe -PathType Leaf)) {
    throw "Build reported success, but output was not found: $OutputExe"
}

Write-Host "built=$OutputExe"
Write-Host "run=not-started"
