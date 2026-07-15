[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string[]]$GossipPeer,
    [Parameter(Mandatory = $true)][string[]]$ForkRpcPeer,
    [Parameter(Mandatory = $true)][string[]]$ForkP2pPeer,
    [string]$DataDir = (Join-Path $HOME ".pohw-agent\pohw-experiment-0"),
    [ValidateSet("registration", "fork-sync", "mining")][string]$LaunchPhase = "registration",
    [string]$ExplorerUrl,
    [string]$SnapshotDir,
    [Nullable[UInt32]]$SnapshotMinVoters,
    [switch]$AllowPrivatePeers,
    [switch]$VerifyTests,
    [switch]$NoOpen
)

$ErrorActionPreference = "Stop"
$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ActivationManifest = Join-Path $RootDir "compatibility\experiment-0-activation.json"

if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw "git is required" }
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { throw "Cargo is required" }
$dirty = (& git -C $RootDir status --porcelain=v1 --untracked-files=all | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { throw "Unable to inspect the source worktree" }
if ($dirty) { throw "Source worktree is dirty; use a clean committed checkout" }
$ignored = (& git -C $RootDir ls-files --others --ignored --exclude-standard --directory | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { throw "Unable to inspect ignored source files" }
if ($ignored) { throw "Source tree contains ignored files or directories; use a fresh checkout" }

if ($LaunchPhase -eq "mining") {
    if (-not $SnapshotDir -or $null -eq $SnapshotMinVoters -or $SnapshotMinVoters -eq 0) {
        throw "Mining requires -SnapshotDir and a positive -SnapshotMinVoters"
    }
}
elseif ($SnapshotDir -or $null -ne $SnapshotMinVoters) {
    throw "Snapshot options are accepted only with -LaunchPhase mining"
}

$BuildRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("pohw-source-build-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $BuildRoot | Out-Null
$buildEnvNames = @(
    "CARGO_TARGET_DIR", "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
    "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTC",
    "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_TARGET"
)
$oldBuildEnv = @{}
foreach ($name in $buildEnvNames) {
    $oldBuildEnv[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
    [Environment]::SetEnvironmentVariable($name, $null, "Process")
}
$env:CARGO_TARGET_DIR = $BuildRoot
$locationPushed = $false
try {
    Push-Location -LiteralPath $RootDir
    $locationPushed = $true
    Write-Host "Building pohw-agent and p2pool-node from the local locked source tree..."
    & cargo build --manifest-path (Join-Path $RootDir "Cargo.toml") --locked --release -p p2pool-node -p pohw-agent
    if ($LASTEXITCODE -ne 0) { throw "Local source build failed" }
    if ($VerifyTests) {
        & cargo test --manifest-path (Join-Path $RootDir "Cargo.toml") --locked -p p2pool-node -p pohw-agent
        if ($LASTEXITCODE -ne 0) { throw "Focused Rust tests failed" }
    }

    $Agent = Join-Path $BuildRoot "release\pohw-agent.exe"
    $Node = Join-Path $BuildRoot "release\p2pool-node.exe"
    if (-not (Test-Path -LiteralPath $Agent -PathType Leaf) -or -not (Test-Path -LiteralPath $Node -PathType Leaf)) {
        throw "Local source build did not produce the expected executables"
    }

    $joinArgs = @(
        "join-source",
        "--source-root", $RootDir,
        "--build-root", $BuildRoot,
        "--p2pool-node", $Node,
        "--activation-manifest", $ActivationManifest,
        "--datadir", $DataDir,
        "--launch-phase", $LaunchPhase
    )
    foreach ($peer in $GossipPeer) { $joinArgs += @("--gossip-peer", $peer) }
    foreach ($peer in $ForkRpcPeer) { $joinArgs += @("--fork-rpc-peer", $peer) }
    foreach ($peer in $ForkP2pPeer) { $joinArgs += @("--fork-p2p-peer", $peer) }
    if ($ExplorerUrl) { $joinArgs += @("--explorer-url", $ExplorerUrl) }
    if ($LaunchPhase -eq "mining") {
        $joinArgs += @(
            "--snapshot-dir", $SnapshotDir,
            "--snapshot-min-voters", "$SnapshotMinVoters"
        )
    }
    if ($AllowPrivatePeers) { $joinArgs += "--allow-private-peers" }
    if ($NoOpen) { $joinArgs += "--no-open" }
    & $Agent @joinArgs
    if ($LASTEXITCODE -ne 0) { throw "pohw-agent exited with code $LASTEXITCODE" }
}
finally {
    if ($locationPushed) { Pop-Location }
    if (Test-Path -LiteralPath $BuildRoot -PathType Container) {
        Remove-Item -LiteralPath $BuildRoot -Recurse -Force
    }
    foreach ($name in $buildEnvNames) {
        [Environment]::SetEnvironmentVariable($name, $oldBuildEnv[$name], "Process")
    }
}
