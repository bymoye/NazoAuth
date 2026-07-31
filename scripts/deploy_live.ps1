param(
    [Parameter(Mandatory = $true)]
    [string]$RemoteHost,
    [Parameter(Mandatory = $true)]
    [string]$BackendCommit,
    [Parameter(Mandatory = $true)]
    [string]$FrontendCommit,
    [string]$ExpectedBackendBranch = "main",
    [string]$ExpectedFrontendBranch = "main",
    [string]$LocalFrontendWorktree = "",
    [string]$LocalBackendWorktree = ".",
    [string]$LocalImageArchive = "",
    [string]$ImageRepository = "localhost/nazo-oauth-server",
    [string]$ImageTag = "",
    [string]$ContainerName = "nazo-oauth-server",
    [string]$Network = "nazo_oauth_net",
    [string]$NetworkSubnet = "10.101.0.0/24",
    [string]$NetworkGateway = "10.101.0.1",
    [string]$IPAddress = "10.101.0.20",
    [string]$RemoteConfigPath = "/opt/nazo-oauth/.env.yaml",
    [string]$RemoteKeysPath = "/opt/nazo-oauth/runtime/keys",
    [string]$RemoteAvatarsPath = "/opt/nazo-oauth/runtime/avatars",
    [string]$RemoteCibaPingTlsTrustBundlePath = "",
    [string]$ContainerCibaPingTlsTrustBundlePath = "/app/ciba-ping-trust-bundle.pem",
    [string]$RemoteUiPath = "/usr/local/angie/html/auth/ui",
    [string]$RemoteUiReleasesRoot = "/usr/local/angie/html/auth-releases",
    [string]$RemoteAngieConfigPath = "/usr/local/angie/conf/conf.d/oauth.conf",
    [string]$AngieWorkerUser = "www",
    [string]$RemoteDeploymentRoot = "/opt/nazo-oauth",
    [string]$LocalUiDist = "",
    [string]$PublishPort = "",
    [string]$HealthUrl = "",
    [string]$DiscoveryUrl = "",
    [string]$UiUrl = "",
    [Parameter(Mandatory = $true)]
    [string]$ExpectedIssuer,
    [ValidateRange(1, 3600)]
    [int]$VerificationLeaseSeconds = 120,
    [string]$RenderRemoteScriptPath = "",
    [string]$RenderRemoteTempDir = "/tmp/nazo-oauth-deploy.render",
    [switch]$SkipBuild,
    [switch]$SkipFrontendBuild,
    [switch]$SkipMigrate,
    [switch]$NoCacheBuild
)

$ErrorActionPreference = "Stop"
$ExpectedBackendRemote = "https://github.com/nazozero/NazoAuth"
$ExpectedFrontendRemote = "https://github.com/nazozero/NazoAuthWeb"

if ($RemoteHost.StartsWith('-') -or
    $RemoteHost -notmatch '^(?:[A-Za-z0-9_][A-Za-z0-9._-]*@)?[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$') {
    throw "RemoteHost must be a safe SSH host alias, hostname, or user@host"
}
$SshOptions = @(
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=30",
    "-o", "ServerAliveInterval=15",
    "-o", "ServerAliveCountMax=4"
)
$ScpOptions = $SshOptions
if ($RemoteUiPath -notmatch '^/' -or $RemoteUiReleasesRoot -notmatch '^/') {
    throw "RemoteUiPath and RemoteUiReleasesRoot must be absolute Linux paths"
}
if ($RemoteCibaPingTlsTrustBundlePath -and (
    $RemoteCibaPingTlsTrustBundlePath -notmatch '^/' -or
    $RemoteCibaPingTlsTrustBundlePath.Contains("`n") -or
    $RemoteCibaPingTlsTrustBundlePath.Contains("`r"))) {
    throw "RemoteCibaPingTlsTrustBundlePath must be an absolute Linux path when provided"
}
if ($ContainerCibaPingTlsTrustBundlePath -notmatch '^/' -or
    $ContainerCibaPingTlsTrustBundlePath.Contains("`n") -or
    $ContainerCibaPingTlsTrustBundlePath.Contains("`r")) {
    throw "ContainerCibaPingTlsTrustBundlePath must be an absolute Linux path"
}
if ($RemoteAngieConfigPath -notmatch '^/' -or $RemoteAngieConfigPath -eq '/' -or
    $RemoteAngieConfigPath.Contains("`n") -or $RemoteAngieConfigPath.Contains("`r")) {
    throw "RemoteAngieConfigPath must be a safe absolute non-root Linux path"
}
if ($ExpectedIssuer -notmatch '^https://[^/?#,\s]+/?$') {
    throw "ExpectedIssuer must be an HTTPS origin without path, query, or fragment"
}
$ExpectedIssuer = $ExpectedIssuer.TrimEnd('/')
if ([string]::IsNullOrWhiteSpace($HealthUrl)) {
    $HealthUrl = "$ExpectedIssuer/health"
}
if ([string]::IsNullOrWhiteSpace($DiscoveryUrl)) {
    $DiscoveryUrl = "$ExpectedIssuer/.well-known/openid-configuration"
}
if ([string]::IsNullOrWhiteSpace($UiUrl)) {
    $UiUrl = "$ExpectedIssuer/ui/auth"
}
if ($RemoteUiPath -eq '/' -or $RemoteUiReleasesRoot -eq '/' -or
    $RemoteUiPath.TrimEnd('/') -eq $RemoteUiReleasesRoot.TrimEnd('/')) {
    throw "RemoteUiPath and RemoteUiReleasesRoot must be distinct non-root paths"
}
if ($AngieWorkerUser -notmatch '^[a-z_][a-z0-9_-]*[$]?$') {
    throw "AngieWorkerUser must be a safe Linux account name"
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
    )
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed: $FilePath $($Arguments -join ' ')"
    }
}

function Get-CommandOutput {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
    )
    $output = & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed: $FilePath $($Arguments -join ' ')"
    }
    return ($output | Select-Object -First 1)
}

function Invoke-SshChecked {
    param([Parameter(Mandatory = $true)][string[]]$RemoteArguments)
    Invoke-Checked ssh @($SshOptions + $RemoteHost + $RemoteArguments)
}

function Get-SshCommandOutput {
    param([Parameter(Mandatory = $true)][string[]]$RemoteArguments)
    Get-CommandOutput ssh @($SshOptions + $RemoteHost + $RemoteArguments)
}

function Invoke-ScpChecked {
    param([Parameter(Mandatory = $true)][string[]]$ScpArguments)
    Invoke-Checked scp @($ScpOptions + $ScpArguments)
}

function Get-GitHubApiJson {
    param([Parameter(Mandatory = $true)][string]$Endpoint)
    $output = & gh api $Endpoint
    if ($LASTEXITCODE -ne 0) {
        throw "GitHub API request failed: $Endpoint"
    }
    try {
        return ($output -join "`n") | ConvertFrom-Json
    }
    catch {
        throw "GitHub API returned invalid JSON for $Endpoint"
    }
}

function ConvertTo-ShellLiteral {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    $singleQuote = [string][char]39
    $escapedQuote = $singleQuote + "\" + $singleQuote + $singleQuote
    return $singleQuote + $Value.Replace($singleQuote, $escapedQuote) + $singleQuote
}

function Write-Utf8LfFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )
    $normalized = $Content.Replace("`r`n", "`n").Replace("`r", "`n")
    [System.IO.File]::WriteAllText(
        $Path,
        $normalized,
        [System.Text.UTF8Encoding]::new($false)
    )
}

function Get-ArchiveImageConfigId {
    param(
        [Parameter(Mandatory = $true)][string]$Archive,
        [Parameter(Mandatory = $true)][string]$ExpectedTag
    )
    $manifestJson = & tar -xOf $Archive "manifest.json"
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read manifest.json from image archive: $Archive"
    }
    $entries = @($manifestJson | ConvertFrom-Json)
    $matching = @($entries | Where-Object { $_.RepoTags -contains $ExpectedTag })
    if ($matching.Count -ne 1) {
        throw "Image archive must contain exactly one manifest for $ExpectedTag"
    }
    $configPath = [string]$matching[0].Config
    if ($configPath -notmatch '^blobs/sha256/(?<digest>[0-9a-f]{64})$') {
        throw "Image archive contains an invalid immutable config path: $configPath"
    }
    return $Matches.digest
}

function Assert-CleanGitCommit {
    param(
        [Parameter(Mandatory = $true)][string]$Worktree,
        [Parameter(Mandatory = $true)][string]$ExpectedCommit,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $root = Get-CommandOutput git @("-C", $Worktree, "rev-parse", "--show-toplevel")
    $actualCommit = Get-CommandOutput git @("-C", $root, "rev-parse", "HEAD")
    if ($actualCommit -cne $ExpectedCommit) {
        throw "$Label HEAD $actualCommit does not match requested commit $ExpectedCommit"
    }
    $status = & git -c core.fsmonitor=false -c core.untrackedCache=false -C $root status --porcelain=v1 --untracked-files=all
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to inspect $Label worktree: $root"
    }
    if ($status) {
        throw "$Label worktree must be clean (tracked and untracked build inputs): $root"
    }
    return [System.IO.Path]::GetFullPath($root)
}

function ConvertTo-GitHubRepositoryIdentity {
    param([Parameter(Mandatory = $true)][string]$Remote)
    $trimmed = $Remote.Trim()
    $patterns = @(
        '^(?:https?://)github\.com/(?<owner>[^/]+)/(?<repository>[^/]+?)(?:\.git)?/?$',
        '^git@github\.com:(?<owner>[^/]+)/(?<repository>[^/]+?)(?:\.git)?/?$',
        '^ssh://git@github\.com/(?<owner>[^/]+)/(?<repository>[^/]+?)(?:\.git)?/?$'
    )
    foreach ($pattern in $patterns) {
        if ($trimmed -match $pattern) {
            return "$($Matches.owner.ToLowerInvariant())/$($Matches.repository.ToLowerInvariant())"
        }
    }
    throw "Unsupported GitHub remote URL: $Remote"
}

function Assert-GitOrigin {
    param(
        [Parameter(Mandatory = $true)][string]$Worktree,
        [Parameter(Mandatory = $true)][string]$ExpectedRemote,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $actual = Get-CommandOutput git @("-C", $Worktree, "remote", "get-url", "origin")
    try {
        $normalizedActual = ConvertTo-GitHubRepositoryIdentity -Remote $actual
    }
    catch {
        throw "$Label origin $actual is not a supported GitHub SSH or HTTPS remote"
    }
    $normalizedExpected = ConvertTo-GitHubRepositoryIdentity -Remote $ExpectedRemote
    if ($normalizedActual -cne $normalizedExpected) {
        throw "$Label origin $actual does not identify expected repository $normalizedExpected"
    }
}

function Assert-SynchronizedGitUpstream {
    param(
        [Parameter(Mandatory = $true)][string]$Worktree,
        [Parameter(Mandatory = $true)][string]$ExpectedBranch,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $upstream = & git -C $Worktree rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $upstream) {
        throw "$Label branch $ExpectedBranch must have an upstream"
    }
    $upstream = $upstream | Select-Object -First 1
    $expectedUpstream = "origin/$ExpectedBranch"
    if ($upstream -cne $expectedUpstream) {
        throw "$Label upstream $upstream does not match expected upstream $expectedUpstream"
    }
    $divergence = Get-CommandOutput git @(
        "-C", $Worktree, "rev-list", "--left-right", "--count", "HEAD...@{upstream}"
    )
    if ($divergence -notmatch '^\s*(?<ahead>\d+)\s+(?<behind>\d+)\s*$') {
        throw "Unable to parse $Label upstream divergence: $divergence"
    }
    if ([int]$Matches.ahead -ne 0 -or [int]$Matches.behind -ne 0) {
        throw "$Label branch $ExpectedBranch is not synchronized with $upstream (ahead $($Matches.ahead), behind $($Matches.behind))"
    }
}

function Assert-FrontendWorktree {
    param(
        [Parameter(Mandatory = $true)][string]$Worktree,
        [Parameter(Mandatory = $true)][string]$ExpectedCommit
    )
    $root = Assert-CleanGitCommit -Worktree $Worktree -ExpectedCommit $ExpectedCommit -Label "Frontend"
    $branch = Get-CommandOutput git @("-C", $root, "branch", "--show-current")
    if ($branch -cne $ExpectedFrontendBranch) {
        throw "Frontend branch $branch does not match expected branch $ExpectedFrontendBranch"
    }
    Assert-GitOrigin -Worktree $root -ExpectedRemote $ExpectedFrontendRemote -Label "Frontend"
    Assert-SynchronizedGitUpstream -Worktree $root -ExpectedBranch $ExpectedFrontendBranch -Label "Frontend"
    return $root
}

function Find-FrontendWorktree {
    param(
        [Parameter(Mandatory = $true)][string]$BackendWorktree,
        [Parameter(Mandatory = $true)][string]$ExpectedCommit
    )
    $commonGitDir = Get-CommandOutput git @(
        "-C", $BackendWorktree, "rev-parse", "--path-format=absolute", "--git-common-dir"
    )
    $backendRepository = Split-Path -Parent $commonGitDir
    $siblingRoot = Split-Path -Parent $backendRepository
    $candidate = Join-Path $siblingRoot "NazoAuthWeb"
    if (-not (Test-Path -LiteralPath $candidate -PathType Container)) {
        throw "Expected frontend worktree does not exist at $candidate. Pass LocalFrontendWorktree explicitly."
    }
    return Assert-FrontendWorktree -Worktree $candidate -ExpectedCommit $ExpectedCommit
}

function Export-GitCommit {
    param(
        [Parameter(Mandatory = $true)][string]$Worktree,
        [Parameter(Mandatory = $true)][string]$Commit,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $identifier = [guid]::NewGuid().ToString("N")
    $archivePath = Join-Path ([System.IO.Path]::GetTempPath()) "nazo-$Label-$identifier.tar"
    $exportPath = Join-Path ([System.IO.Path]::GetTempPath()) "nazo-$Label-$identifier"
    New-Item -ItemType Directory -Path $exportPath | Out-Null
    try {
        Invoke-Checked git @("-C", $Worktree, "archive", "--format=tar", "--output=$archivePath", $Commit)
        Invoke-Checked tar @("-xf", $archivePath, "-C", $exportPath)
        return $exportPath
    }
    catch {
        Remove-Item -LiteralPath $exportPath -Recurse -Force -ErrorAction SilentlyContinue
        throw
    }
    finally {
        Remove-Item -LiteralPath $archivePath -Force -ErrorAction SilentlyContinue
    }
}

function Get-FrontendArtifactDigest {
    param([Parameter(Mandatory = $true)][string]$DistPath)
    $root = [System.IO.Path]::GetFullPath($DistPath)
    $reparsePoint = Get-ChildItem -LiteralPath $root -Recurse -Force |
        Where-Object { ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 } |
        Select-Object -First 1
    if ($reparsePoint) {
        throw "Frontend dist must not contain symlinks or reparse points: $($reparsePoint.FullName)"
    }
    $entries = Get-ChildItem -LiteralPath $root -File -Recurse -Force |
        Where-Object { $_.Name -ne ".nazo-build.json" } |
        Sort-Object FullName |
        ForEach-Object {
            $relative = [System.IO.Path]::GetRelativePath($root, $_.FullName).Replace('\', '/')
            $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            "$relative`t$hash`n"
        }
    $canonical = [string]::Concat([string[]]$entries)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($canonical)
    return [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

function Write-FrontendBuildManifest {
    param(
        [Parameter(Mandatory = $true)][string]$DistPath,
        [Parameter(Mandatory = $true)][string]$SourceCommit
    )
    $manifestPath = Join-Path $DistPath ".nazo-build.json"
    $manifest = [ordered]@{
        schema = 1
        source_commit = $SourceCommit
        artifact_sha256 = Get-FrontendArtifactDigest -DistPath $DistPath
    }
    $manifest | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding UTF8
}

if ($BackendCommit -notmatch '^[0-9a-f]{40}$') {
    throw "BackendCommit must be a full lowercase Git SHA"
}
if ($FrontendCommit -notmatch '^[0-9a-f]{40}$') {
    throw "FrontendCommit must be a full lowercase Git SHA"
}
$LocalBackendWorktree = Assert-CleanGitCommit -Worktree $LocalBackendWorktree -ExpectedCommit $BackendCommit -Label "Backend"
$backendBranch = Get-CommandOutput git @("-C", $LocalBackendWorktree, "branch", "--show-current")
if ($backendBranch -cne $ExpectedBackendBranch) {
    throw "Backend branch $backendBranch does not match expected branch $ExpectedBackendBranch"
}
Assert-GitOrigin -Worktree $LocalBackendWorktree -ExpectedRemote $ExpectedBackendRemote -Label "Backend"
if (-not $LocalFrontendWorktree) {
    $LocalFrontendWorktree = Find-FrontendWorktree `
        -BackendWorktree $LocalBackendWorktree `
        -ExpectedCommit $FrontendCommit
}
else {
    $LocalFrontendWorktree = Assert-FrontendWorktree `
        -Worktree $LocalFrontendWorktree `
        -ExpectedCommit $FrontendCommit
}
if (-not $LocalUiDist) {
    $LocalUiDist = Join-Path $LocalFrontendWorktree "dist"
}
$LocalUiDist = [System.IO.Path]::GetFullPath($LocalUiDist)
$frontendRootWithSeparator = $LocalFrontendWorktree.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
if (-not $LocalUiDist.StartsWith($frontendRootWithSeparator, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "LocalUiDist must be inside LocalFrontendWorktree"
}
if (-not $RenderRemoteScriptPath -and $SkipBuild) {
    throw "SkipBuild is only allowed when rendering the remote script for tests"
}
if (-not $RenderRemoteScriptPath -and $SkipFrontendBuild) {
    throw "SkipFrontendBuild is only allowed when rendering the remote script for tests"
}
if ($LocalImageArchive) {
    if ($NoCacheBuild) {
        throw "LocalImageArchive and NoCacheBuild are mutually exclusive"
    }
    $LocalImageArchive = [System.IO.Path]::GetFullPath($LocalImageArchive)
    if (-not (Test-Path -LiteralPath $LocalImageArchive -PathType Leaf)) {
        throw "LocalImageArchive does not exist: $LocalImageArchive"
    }
}
if (-not $ImageTag) {
    $ImageTag = "modular-$($BackendCommit.Substring(0, 7))-web-$($FrontendCommit.Substring(0, 7))"
}
if (-not $SkipFrontendBuild) {
    $frontendBuildContext = Export-GitCommit -Worktree $LocalFrontendWorktree -Commit $FrontendCommit -Label "frontend-source"
    try {
        $packageJsonPath = Join-Path $frontendBuildContext "package.json"
        $packageLockPath = Join-Path $frontendBuildContext "package-lock.json"
        if (-not (Test-Path -LiteralPath $packageJsonPath -PathType Leaf)) {
            throw "Frontend deployment build requires package.json"
        }
        if (-not (Test-Path -LiteralPath $packageLockPath -PathType Leaf)) {
            throw "Frontend deployment build requires package-lock.json"
        }
        try {
            $frontendPackage = Get-Content -LiteralPath $packageJsonPath -Raw | ConvertFrom-Json
        }
        catch {
            throw "Frontend package.json is not valid JSON: $($_.Exception.Message)"
        }
        $packageManager = [string]$frontendPackage.packageManager
        $npmPackageManager = [regex]::Match($packageManager, '^npm@(?<version>\d+\.\d+\.\d+)$')
        if (-not $npmPackageManager.Success) {
            throw "Frontend packageManager must pin an exact npm version; found '$packageManager'"
        }
        $expectedNpmVersion = $npmPackageManager.Groups['version'].Value
        $actualNpmVersion = Get-CommandOutput npm @("--version")
        if ($actualNpmVersion -cne $expectedNpmVersion) {
            throw "Frontend requires npm $expectedNpmVersion but deployment host has npm $actualNpmVersion"
        }
        $testScript = $frontendPackage.scripts.PSObject.Properties['test']
        if ($null -eq $testScript -or [string]::IsNullOrWhiteSpace([string]$testScript.Value)) {
            throw "Frontend package.json must define the verified aggregate test script"
        }
        Invoke-Checked npm @("--prefix", $frontendBuildContext, "ci")
        Invoke-Checked npm @("--prefix", $frontendBuildContext, "run", "test")
        $builtUiDist = Join-Path $frontendBuildContext "dist"
        Remove-Item -LiteralPath $builtUiDist -Recurse -Force -ErrorAction SilentlyContinue
        Invoke-Checked npm @("--prefix", $frontendBuildContext, "run", "build")
        if (-not (Test-Path -LiteralPath (Join-Path $builtUiDist "index.html") -PathType Leaf)) {
            throw "Frontend build did not produce dist/index.html"
        }
        Remove-Item -LiteralPath $LocalUiDist -Recurse -Force -ErrorAction SilentlyContinue
        Copy-Item -LiteralPath $builtUiDist -Destination $LocalUiDist -Recurse
    }
    finally {
        Remove-Item -LiteralPath $frontendBuildContext -Recurse -Force -ErrorAction SilentlyContinue
    }
    $LocalFrontendWorktree = Assert-FrontendWorktree `
        -Worktree $LocalFrontendWorktree `
        -ExpectedCommit $FrontendCommit
}
if (-not (Test-Path -LiteralPath (Join-Path $LocalUiDist "index.html") -PathType Leaf)) {
    throw "Missing frontend dist index.html: $LocalUiDist"
}
Write-FrontendBuildManifest -DistPath $LocalUiDist -SourceCommit $FrontendCommit
$frontendArtifactDigest = Get-FrontendArtifactDigest -DistPath $LocalUiDist

$image = "${ImageRepository}:$ImageTag"
$safeTag = $ImageTag -replace '[^A-Za-z0-9_.-]', '-'
$deploymentId = [guid]::NewGuid().ToString("N")
$localStageSuffix = "$safeTag-$deploymentId"
$archive = Join-Path ([System.IO.Path]::GetTempPath()) "nazo-oauth-server-$localStageSuffix.tar"
$uiArchive = Join-Path ([System.IO.Path]::GetTempPath()) "nazo-oauth-web-$localStageSuffix.tar.gz"
$localRemoteScript = Join-Path ([System.IO.Path]::GetTempPath()) "nazo-oauth-deploy-$localStageSuffix.sh"

Write-Host "Staging $image ($BackendCommit / $FrontendCommit) on $RemoteHost"

$expectedImageId = "0" * 64
if ($RenderRemoteScriptPath) {
    $remoteTempDir = $RenderRemoteTempDir
}
else {
    if ($LocalImageArchive) {
        Invoke-Checked docker @("load", "-i", $LocalImageArchive)
    }
    else {
        $backendBuildContext = Export-GitCommit -Worktree $LocalBackendWorktree -Commit $BackendCommit -Label "backend-source"
        try {
            $dockerBuildArgs = @(
                "build", "-f", (Join-Path $backendBuildContext "Containerfile"),
                "--target", "runtime",
                "--label", "org.opencontainers.image.revision=$BackendCommit",
                "-t", $image
            )
            if ($NoCacheBuild) {
                $dockerBuildArgs += "--no-cache"
            }
            $dockerBuildArgs += $backendBuildContext
            Invoke-Checked docker $dockerBuildArgs
        }
        finally {
            Remove-Item -LiteralPath $backendBuildContext -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $LocalBackendWorktree = Assert-CleanGitCommit -Worktree $LocalBackendWorktree -ExpectedCommit $BackendCommit -Label "Backend after build"
    $localDescriptorId = Get-CommandOutput docker @("image", "inspect", $image, "--format", "{{.Id}}")
    if ($localDescriptorId -notmatch '^sha256:[0-9a-f]{64}$') {
        throw "Docker returned an invalid immutable image descriptor: $localDescriptorId"
    }
    $localRevision = Get-CommandOutput docker @(
        "image", "inspect", $image,
        "--format", '{{index .Config.Labels "org.opencontainers.image.revision"}}'
    )
    if ($localRevision -cne $BackendCommit) {
        throw "Image revision $localRevision does not match backend commit $BackendCommit"
    }
    Remove-Item -LiteralPath $archive, $uiArchive -Force -ErrorAction SilentlyContinue
    Invoke-Checked docker @("save", $image, "-o", $archive)
    $expectedImageId = Get-ArchiveImageConfigId -Archive $archive -ExpectedTag $image
    Invoke-Checked tar @("-C", $LocalUiDist, "-czf", $uiArchive, ".")
    $remoteTempDir = Get-SshCommandOutput @("mktemp", "-d", "/tmp/nazo-oauth-deploy.XXXXXX")
}
$remoteArchive = "$remoteTempDir/nazo-oauth-server-$safeTag.tar"
$remoteUiArchive = "$remoteTempDir/nazo-oauth-web-$safeTag.tar.gz"
$remoteScript = "$remoteTempDir/deploy.sh"
$remoteState = "$remoteTempDir/state.json"
if (-not $RenderRemoteScriptPath) {
    Invoke-ScpChecked @($archive, "${RemoteHost}:$remoteArchive")
    Invoke-ScpChecked @($uiArchive, "${RemoteHost}:$remoteUiArchive")
}

$skipMigrateValue = if ($SkipMigrate) { "1" } else { "0" }
$remoteBody = @"
#!/usr/bin/env bash
set -euo pipefail
umask 077

IMAGE=$(ConvertTo-ShellLiteral $image)
BACKEND_COMMIT=$(ConvertTo-ShellLiteral $BackendCommit)
FRONTEND_COMMIT=$(ConvertTo-ShellLiteral $FrontendCommit)
FRONTEND_ARTIFACT_SHA256=$(ConvertTo-ShellLiteral $frontendArtifactDigest)
DEPLOYMENT_ID=$(ConvertTo-ShellLiteral $deploymentId)
REMOTE_ARCHIVE=$(ConvertTo-ShellLiteral $remoteArchive)
REMOTE_UI_ARCHIVE=$(ConvertTo-ShellLiteral $remoteUiArchive)
REMOTE_SCRIPT=$(ConvertTo-ShellLiteral $remoteScript)
STATE_FILE=$(ConvertTo-ShellLiteral $remoteState)
CONTAINER_NAME=$(ConvertTo-ShellLiteral $ContainerName)
NETWORK_NAME=$(ConvertTo-ShellLiteral $Network)
NETWORK_SUBNET=$(ConvertTo-ShellLiteral $NetworkSubnet)
NETWORK_GATEWAY=$(ConvertTo-ShellLiteral $NetworkGateway)
CONTAINER_IP=$(ConvertTo-ShellLiteral $IPAddress)
CONFIG_PATH=$(ConvertTo-ShellLiteral $RemoteConfigPath)
KEYS_PATH=$(ConvertTo-ShellLiteral $RemoteKeysPath)
AVATARS_PATH=$(ConvertTo-ShellLiteral $RemoteAvatarsPath)
CIBA_PING_TLS_TRUST_BUNDLE_PATH=$(ConvertTo-ShellLiteral $RemoteCibaPingTlsTrustBundlePath)
CIBA_PING_TLS_TRUST_BUNDLE_CONTAINER_PATH=$(ConvertTo-ShellLiteral $ContainerCibaPingTlsTrustBundlePath)
UI_PATH=$(ConvertTo-ShellLiteral $RemoteUiPath)
UI_RELEASES=$(ConvertTo-ShellLiteral $RemoteUiReleasesRoot)
ANGIE_WORKER_USER=$(ConvertTo-ShellLiteral $AngieWorkerUser)
DEPLOYMENT_ROOT=$(ConvertTo-ShellLiteral $RemoteDeploymentRoot)
PUBLISH_PORT=$(ConvertTo-ShellLiteral $PublishPort)
EXPECTED_ISSUER=$(ConvertTo-ShellLiteral $ExpectedIssuer)
EXPECTED_IMAGE_ID=$(ConvertTo-ShellLiteral $expectedImageId)
SKIP_MIGRATE=$(ConvertTo-ShellLiteral $skipMigrateValue)
VERIFICATION_LEASE_SECONDS=$(ConvertTo-ShellLiteral $VerificationLeaseSeconds)
ANGIE_CONFIG=$(ConvertTo-ShellLiteral $RemoteAngieConfigPath)

DEPLOYMENTS="`$DEPLOYMENT_ROOT/deployments"
UI_RELEASE="`$UI_RELEASES/`$FRONTEND_COMMIT"
RECORD="`$DEPLOYMENTS/`$BACKEND_COMMIT-`$FRONTEND_COMMIT-`$DEPLOYMENT_ID.json"
CURRENT_LINK_TEMP="`$DEPLOYMENTS/.current-`$DEPLOYMENT_ID"
ACTIVE_DEPLOYMENT="`$DEPLOYMENTS/active-deployment"
LEASE_PENDING="`$STATE_FILE.lease-pending"
LEASE_COMMITTED="`$STATE_FILE.lease-committed"
LEASE_ROLLBACK="`$STATE_FILE.lease-rollback"
LEASE_LOCK="`$DEPLOYMENTS/lease.lock"
WATCHDOG_PID_FILE="`$STATE_FILE.watchdog-pid"
KEYS_SNAPSHOT="`$STATE_FILE.keys-before.tar"
KEYS_SNAPSHOT_DIGEST="`$STATE_FILE.keys-before.sha256"
KEYS_PARENT="`$(dirname "`$KEYS_PATH")"
KEYS_BASENAME="`$(basename "`$KEYS_PATH")"
KEYS_RESTORE_DIR="`$KEYS_PARENT/.`$KEYS_BASENAME.restore-`$DEPLOYMENT_ID"
KEYS_FAILED_DIR="`$KEYS_PARENT/.`$KEYS_BASENAME.failed-`$DEPLOYMENT_ID"

run_server() {
  local selected_image="`$1"
  local publish_args=()
  local ciba_ping_tls_args=()
  if [ -n "`$PUBLISH_PORT" ]; then publish_args=(-p "`$PUBLISH_PORT"); fi
  if [ -n "`$CIBA_PING_TLS_TRUST_BUNDLE_PATH" ]; then
    test -f "`$CIBA_PING_TLS_TRUST_BUNDLE_PATH"
    test ! -L "`$CIBA_PING_TLS_TRUST_BUNDLE_PATH"
    ciba_ping_tls_args=(
      -e "CIBA_PING_TLS_TRUST_BUNDLE=`$CIBA_PING_TLS_TRUST_BUNDLE_CONTAINER_PATH"
      -v "`$CIBA_PING_TLS_TRUST_BUNDLE_PATH:`$CIBA_PING_TLS_TRUST_BUNDLE_CONTAINER_PATH:ro"
    )
  fi
  podman run -d --name "`$CONTAINER_NAME" \
    --restart=unless-stopped \
    --network "`$NETWORK_NAME" --ip "`$CONTAINER_IP" \
    "`${publish_args[@]}" \
    "`${ciba_ping_tls_args[@]}" \
    -v "`$CONFIG_PATH:/app/.env.yaml:ro" \
    -v "`$KEYS_PATH:/var/lib/nazo_oauth/keys:rw" \
    -v "`$AVATARS_PATH:/var/lib/nazo_oauth/avatars:rw" \
    "`$selected_image" nazoauth server >/dev/null
}

fsync_parent() {
  python3 - "`$1" <<'PY'
import os, pathlib, sys
if os.name == "nt":
    raise SystemExit(0)
parent = pathlib.Path(sys.argv[1]).parent
descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

sha256_file() {
  local digest_file output
  digest_file="`$(mktemp)" || return 1
  if ! sha256sum -- "`$1" >"`$digest_file"; then
    rm -f "`$digest_file"
    echo "sha256sum failed for `$1" >&2
    return 1
  fi
  if ! output="`$(python3 - "`$digest_file" <<'PY'
import pathlib
import re
import sys

raw = pathlib.Path(sys.argv[1]).read_bytes()
match = re.fullmatch(rb"([0-9a-f]{64}) [ *][^\r\n]+\n", raw)
if match is None:
    raise SystemExit(1)
print(match.group(1).decode("ascii"))
PY
)"; then
    rm -f "`$digest_file"
    echo "sha256sum returned malformed or multiline output for `$1" >&2
    return 1
  fi
  rm -f "`$digest_file" || return 1
  printf '%s\n' "`$output"
}

require_sha256() {
  local actual
  if ! actual="`$(sha256_file "`$1")"; then
    return 1
  fi
  if [ "`$actual" != "`$2" ]; then
    echo "SHA-256 mismatch for `$3" >&2
    return 1
  fi
}

create_keys_snapshot() {
  local snapshot_temp digest_temp digest
  snapshot_temp="`$KEYS_SNAPSHOT.tmp"
  digest_temp="`$KEYS_SNAPSHOT_DIGEST.tmp"
  rm -f "`$snapshot_temp" "`$digest_temp"
  tar -C "`$KEYS_PATH" -cpf "`$snapshot_temp" .
  chmod 0600 "`$snapshot_temp"
  digest="`$(sha256_file "`$snapshot_temp")"
  printf '%s\n' "`$digest" >"`$digest_temp"
  chmod 0600 "`$digest_temp"
  mv -f "`$snapshot_temp" "`$KEYS_SNAPSHOT"
  mv -f "`$digest_temp" "`$KEYS_SNAPSHOT_DIGEST"
  fsync_parent "`$KEYS_SNAPSHOT"
}

restore_keys_snapshot() {
  local expected_digest actual_digest
  test -f "`$KEYS_SNAPSHOT"
  test ! -L "`$KEYS_SNAPSHOT"
  test -f "`$KEYS_SNAPSHOT_DIGEST"
  test ! -L "`$KEYS_SNAPSHOT_DIGEST"
  expected_digest="`$(cat "`$KEYS_SNAPSHOT_DIGEST")"
  [[ "`$expected_digest" =~ ^[0-9a-f]{64}`$ ]]
  actual_digest="`$(sha256_file "`$KEYS_SNAPSHOT")"
  test "`$actual_digest" = "`$expected_digest"
  test -d "`$KEYS_PATH"
  test ! -L "`$KEYS_PATH"
  rm -rf "`$KEYS_RESTORE_DIR" "`$KEYS_FAILED_DIR"
  install -d -m 0700 "`$KEYS_RESTORE_DIR"
  tar -xpf "`$KEYS_SNAPSHOT" -C "`$KEYS_RESTORE_DIR"
  mv -T "`$KEYS_PATH" "`$KEYS_FAILED_DIR"
  if ! mv -T "`$KEYS_RESTORE_DIR" "`$KEYS_PATH"; then
    mv -T "`$KEYS_FAILED_DIR" "`$KEYS_PATH" || true
    return 1
  fi
  fsync_parent "`$KEYS_PATH"
}

secure_angie_config_sha256() {
  python3 - "`$ANGIE_CONFIG" <<'PY'
import hashlib
import os
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(path, flags)
try:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit("Angie config must be a regular file")
    if os.name == "posix":
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise SystemExit("Angie config must be root-owned and not group/world-writable")
        for parent in (path.parent, *path.parents):
            parent_metadata = os.stat(parent, follow_symlinks=False)
            if (
                not stat.S_ISDIR(parent_metadata.st_mode)
                or parent_metadata.st_uid != 0
                or parent_metadata.st_mode & 0o022
            ):
                raise SystemExit(
                    "Angie config parent directories must be root-owned and not group/world-writable"
                )
    with os.fdopen(descriptor, "rb", closefd=False) as source:
        digest = hashlib.sha256(source.read()).hexdigest()
finally:
    os.close(descriptor)
print(digest)
PY
}

assert_angie_backend_upstream() {
  local active_config
  secure_angie_config_sha256 >/dev/null || return 1
  test -f "`$ANGIE_CONFIG" || return 1
  test ! -L "`$ANGIE_CONFIG" || return 1
  if ! active_config="`$(angie -T 2>&1)"; then
    echo "Angie configuration dump failed" >&2
    return 1
  fi
  grep -F "# configuration file `$ANGIE_CONFIG:" <<<"`$active_config" >/dev/null || {
    echo "`$ANGIE_CONFIG is not present in the active Angie configuration" >&2
    return 1
  }
  python3 - "`$ANGIE_CONFIG" "`$CONTAINER_IP" <<'PY'
from __future__ import annotations

import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
container_ip = sys.argv[2]
source = path.read_text(encoding="utf-8")
if "\x00" in source:
    raise SystemExit("Angie config contains a NUL byte")
matches = re.findall(r"proxy_pass\s+http://(?P<host>10\.101\.0\.\d+):8000\s*;", source)
if matches != [container_ip]:
    raise SystemExit(
        f"Angie backend proxy_pass must point only to {container_ip}:8000, got {matches}"
    )
if re.search(r"https?://(?:127\.0\.0\.1|localhost|\[::1\])(?::[0-9]+)?", source):
    raise SystemExit("local conformance-suite upstreams are forbidden in production Angie configuration")
PY
}

write_record() {
  local status="`$1"
  python3 - "`$RECORD" "`$status" "`$BACKEND_COMMIT" "`$FRONTEND_COMMIT" \
    "`$DEPLOYMENT_ID" "`$IMAGE" "`$EXPECTED_IMAGE_ID" "`$FRONTEND_ARTIFACT_SHA256" \
    "`${previous_image_id:-}" "`${previous_image_name:-}" \
    "`${previous_container_id:-}" "`${previous_ui_target:-}" "`${candidate_container_id:-}" \
    "`$UI_RELEASE" <<'PY'
import json, os, pathlib, sys, time
path = pathlib.Path(sys.argv[1])
payload = {
    "status": sys.argv[2],
    "backend_commit": sys.argv[3],
    "frontend_commit": sys.argv[4],
    "deployment_id": sys.argv[5],
    "candidate_image": sys.argv[6],
    "candidate_image_id": sys.argv[7],
    "frontend_artifact_sha256": sys.argv[8],
    "previous_image_id": sys.argv[9],
    "previous_image_name": sys.argv[10],
    "previous_container_id": sys.argv[11],
    "previous_ui_target": sys.argv[12],
    "candidate_container_id": sys.argv[13],
    "candidate_ui_release": sys.argv[14],
    "recorded_at_unix": int(time.time()),
}
path.parent.mkdir(parents=True, exist_ok=True)
temporary = path.with_suffix(".json.tmp")
with temporary.open("w", encoding="utf-8") as handle:
    handle.write(json.dumps(payload, sort_keys=True) + "\n")
    handle.flush()
    os.fsync(handle.fileno())
temporary.replace(path)
if os.name != "nt":
    descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
PY
}

save_state() {
  local state_dir state_temp
  state_dir="`$(dirname "`$STATE_FILE")"
  state_temp="`$(mktemp "`$state_dir/.state.XXXXXX")"
  chmod 0600 "`$state_temp"
  if ! python3 - "`$state_temp" "`$DEPLOYMENT_ID" \
    "`$previous_image_id" "`$previous_image_name" "`$previous_container_id" \
    "`$previous_ui_kind" "`$previous_ui_target" "`$legacy_ui_release" \
    "`$candidate_container_id" "`$previous_current_target" \
    "`$candidate_started" "`$ui_switched" "`$keys_mutation_possible" <<'PY'
import json, os, sys
keys = (
    "deployment_id", "previous_image_id", "previous_image_name",
    "previous_container_id", "previous_ui_kind", "previous_ui_target",
    "legacy_ui_release", "candidate_container_id", "previous_current_target",
    "candidate_started", "ui_switched", "keys_mutation_possible",
)
payload = dict(zip(keys, sys.argv[2:], strict=True))
payload["schema"] = 4
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(payload, handle, sort_keys=True)
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
PY
  then
    rm -f "`$state_temp"
    return 1
  fi
  validate_state_file "`$state_temp" >/dev/null || { rm -f "`$state_temp"; return 1; }
  mv -f "`$state_temp" "`$STATE_FILE"
  fsync_parent "`$STATE_FILE"
}

validate_state_file() {
  python3 - "`$1" "`$DEPLOYMENT_ID" <<'PY'
import json, pathlib, shlex, sys
path = pathlib.Path(sys.argv[1])
try:
    payload = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"invalid deployment state: {error}")
keys = {
    "schema", "deployment_id", "previous_image_id", "previous_image_name",
    "previous_container_id", "previous_ui_kind", "previous_ui_target",
    "legacy_ui_release", "candidate_container_id", "previous_current_target",
    "candidate_started", "ui_switched", "keys_mutation_possible",
}
if set(payload) != keys or payload.get("schema") != 4:
    raise SystemExit("invalid deployment state schema")
if payload.get("deployment_id") != sys.argv[2]:
    raise SystemExit("deployment state owner mismatch")
for key in keys - {"schema"}:
    if not isinstance(payload[key], str) or "\0" in payload[key] or "\n" in payload[key]:
        raise SystemExit(f"invalid deployment state field: {key}")
if payload["previous_ui_kind"] not in {"missing", "symlink", "directory"}:
    raise SystemExit("invalid previous_ui_kind")
if any(
    payload[key] not in {"0", "1"}
    for key in ("candidate_started", "ui_switched", "keys_mutation_possible")
):
    raise SystemExit("invalid deployment state flags")
for key in sorted(keys - {"schema", "deployment_id"}):
    print(f"{key}={shlex.quote(payload[key])}")
PY
}

load_state() {
  test -f "`$STATE_FILE"
  local assignments
  assignments="`$(validate_state_file "`$STATE_FILE")" || return 1
  eval "`$assignments"
}

rollback() {
  load_state || { write_record "rollback-failed" || true; return 1; }
  local image_failed=0 ui_failed=0 pointer_failed=0 restored_image
  if [ "`$keys_mutation_possible" = "1" ]; then
    if podman container exists "`$CONTAINER_NAME" && ! podman rm -f "`$CONTAINER_NAME" >/dev/null; then
      image_failed=1
    fi
    if [ "`$image_failed" = "0" ] && ! restore_keys_snapshot; then
      image_failed=1
    fi
    if [ "`$image_failed" = "0" ] && [ -n "`$previous_image_id" ]; then
      if ! podman image exists "`$previous_image_id"; then
        image_failed=1
      elif ! run_server "`$previous_image_id"; then
        image_failed=1
      fi
    fi
  elif [ "`$candidate_started" = "1" ]; then
    if podman container exists "`$CONTAINER_NAME" && ! podman rm -f "`$CONTAINER_NAME" >/dev/null; then image_failed=1; fi
    if [ -n "`$previous_image_id" ]; then
      if ! podman image exists "`$previous_image_id"; then
        image_failed=1
      elif ! run_server "`$previous_image_id"; then
        image_failed=1
      fi
    fi
  fi
  if [ "`$ui_switched" = "1" ]; then
    if [ "`$previous_ui_kind" = "symlink" ]; then
      if [ -L "`$UI_PATH" ] && [ "`$(readlink "`$UI_PATH")" = "`$previous_ui_target" ]; then
        :
      elif { [ -L "`$UI_PATH" ] || [ -e "`$UI_PATH" ]; } && ! rm -rf "`$UI_PATH"; then
        ui_failed=1
      elif [ -n "`$previous_ui_target" ]; then
        ln -s "`$previous_ui_target" "`$UI_PATH" || ui_failed=1
      else
        ui_failed=1
      fi
    elif [ "`$previous_ui_kind" = "directory" ]; then
      if [ -n "`$legacy_ui_release" ] && [ -d "`$legacy_ui_release" ]; then
        if { [ -L "`$UI_PATH" ] || [ -e "`$UI_PATH" ]; } && ! rm -rf "`$UI_PATH"; then ui_failed=1; fi
        if [ "`$ui_failed" = "0" ]; then mv -T "`$legacy_ui_release" "`$UI_PATH" || ui_failed=1; fi
      elif [ -d "`$UI_PATH" ] && [ ! -L "`$UI_PATH" ]; then
        : # The old directory was never moved; leave it intact.
      else
        ui_failed=1
      fi
    elif { [ -L "`$UI_PATH" ] || [ -e "`$UI_PATH" ]; } && ! rm -rf "`$UI_PATH"; then
      ui_failed=1
    fi
  fi
  if [ -L "`$DEPLOYMENTS/current.json" ] && [ "`$(readlink "`$DEPLOYMENTS/current.json")" = "`$RECORD" ]; then
    if ! rm -f "`$DEPLOYMENTS/current.json"; then
      pointer_failed=1
    elif [ -n "`$previous_current_target" ]; then
      rm -f "`$CURRENT_LINK_TEMP"
      if ln -s "`$previous_current_target" "`$CURRENT_LINK_TEMP" &&
        mv -T "`$CURRENT_LINK_TEMP" "`$DEPLOYMENTS/current.json" &&
        fsync_parent "`$DEPLOYMENTS/current.json"; then
        :
      else
        pointer_failed=1
        rm -f "`$CURRENT_LINK_TEMP" || true
      fi
    elif ! fsync_parent "`$DEPLOYMENTS/current.json"; then
      pointer_failed=1
    fi
  fi
  if [ -n "`$previous_image_id" ]; then
    podman container exists "`$CONTAINER_NAME" || image_failed=1
    restored_image="`$(podman inspect "`$CONTAINER_NAME" --format '{{.Image}}' 2>/dev/null)" || image_failed=1
    [ "`$restored_image" = "`$previous_image_id" ] || image_failed=1
    curl -fsS --max-time 20 "http://`$CONTAINER_IP:8000/health" >/dev/null || image_failed=1
  elif podman container exists "`$CONTAINER_NAME"; then
    image_failed=1
  fi
  if [ "`$previous_ui_kind" = "symlink" ]; then
    [ -L "`$UI_PATH" ] && [ "`$(readlink "`$UI_PATH")" = "`$previous_ui_target" ] || ui_failed=1
  elif [ "`$previous_ui_kind" = "directory" ]; then
    [ -d "`$UI_PATH" ] && [ ! -L "`$UI_PATH" ] || ui_failed=1
  else
    [ ! -e "`$UI_PATH" ] && [ ! -L "`$UI_PATH" ] || ui_failed=1
  fi
  if [ -n "`$previous_current_target" ]; then
    [ -L "`$DEPLOYMENTS/current.json" ] &&
      [ "`$(readlink "`$DEPLOYMENTS/current.json")" = "`$previous_current_target" ] || pointer_failed=1
  else
    [ ! -e "`$DEPLOYMENTS/current.json" ] && [ ! -L "`$DEPLOYMENTS/current.json" ] || pointer_failed=1
  fi
  if [ "`$image_failed" != "0" ] || [ "`$ui_failed" != "0" ] || [ "`$pointer_failed" != "0" ]; then
    write_record "rollback-failed" || true
    return 1
  fi
  rm -rf "`$KEYS_FAILED_DIR"
  write_record "rolled-back"
}

cleanup() {
  rm -f "`$REMOTE_ARCHIVE" "`$REMOTE_UI_ARCHIVE" "`$REMOTE_SCRIPT" "`$STATE_FILE" \
    "`$WATCHDOG_PID_FILE" "`$LEASE_PENDING" "`$LEASE_COMMITTED" "`$LEASE_ROLLBACK" \
    "`$CURRENT_LINK_TEMP" "`$KEYS_SNAPSHOT" "`$KEYS_SNAPSHOT_DIGEST"
  rm -rf "`$UI_RELEASE.tmp" "`$KEYS_RESTORE_DIR" "`$KEYS_FAILED_DIR"
  if [ -f "`$ACTIVE_DEPLOYMENT/owner" ] && [ "`$(cat "`$ACTIVE_DEPLOYMENT/owner")" = "`$DEPLOYMENT_ID" ]; then
    rm -rf "`$ACTIVE_DEPLOYMENT"
  fi
  rmdir "`$(dirname "`$REMOTE_SCRIPT")" 2>/dev/null || true
}

stop_watchdog() {
  if [ -f "`$WATCHDOG_PID_FILE" ]; then
    watchdog_pid="`$(cat "`$WATCHDOG_PID_FILE")"
    if [[ "`$watchdog_pid" =~ ^[0-9]+`$ ]]; then
      kill "`$watchdog_pid" 2>/dev/null || true
    fi
  fi
}

start_verification_lease() {
  local watchdog_pid
  : >"`$LEASE_PENDING"
  nohup bash -c 'sleep "`$1"; exec bash "`$2" expire' _ \
    "`$VERIFICATION_LEASE_SECONDS" "`$REMOTE_SCRIPT" </dev/null >/dev/null 2>&1 &
  watchdog_pid="`$!"
  printf '%s\n' "`$watchdog_pid" >"`$WATCHDOG_PID_FILE"
  kill -0 "`$watchdog_pid"
}

rollback_transaction() {
  trap - ERR
  if [ ! -f "`$STATE_FILE" ]; then return 0; fi
  exec 9>"`$LEASE_LOCK"
  flock -x 9
  if [ ! -f "`$STATE_FILE" ]; then flock -u 9; return 0; fi
  if [ -f "`$LEASE_COMMITTED" ]; then
    echo "Deployment is already committed; refusing rollback" >&2
    return 1
  fi
  if [ -f "`$LEASE_PENDING" ]; then mv "`$LEASE_PENDING" "`$LEASE_ROLLBACK"; fi
  if rollback; then
    stop_watchdog
    flock -u 9
    cleanup
    return 0
  fi
  flock -u 9
  echo "Rollback failed; deployment evidence was preserved at `$STATE_FILE and `$RECORD" >&2
  return 1
}

assert_pending_lease() {
  test -f "`$LEASE_PENDING"
  test -f "`$ACTIVE_DEPLOYMENT/owner"
  test "`$(cat "`$ACTIVE_DEPLOYMENT/owner")" = "`$DEPLOYMENT_ID"
}

rollback_after_deploy_error() {
  trap - ERR
  flock -u 8 2>/dev/null || true
  rollback_transaction
}

deploy() {
  test -f "`$CONFIG_PATH"
  test -d "`$KEYS_PATH"
  test ! -L "`$KEYS_PATH"
  test -d "`$AVATARS_PATH"
  test "`$(df -Pk "`$DEPLOYMENT_ROOT" | awk 'NR==2 {print `$4}')" -gt 1048576
  command -v flock >/dev/null
  podman network exists "`$NETWORK_NAME"
  network_inspect="`$(podman network inspect "`$NETWORK_NAME")"
  if ! python3 - "`$NETWORK_SUBNET" "`$NETWORK_GATEWAY" "`$network_inspect" <<'PY'; then
import json, sys
document = json.loads(sys.argv[3])
if not isinstance(document, list) or len(document) != 1 or not isinstance(document[0], dict):
    raise SystemExit(1)
subnets = document[0].get("subnets")
if not isinstance(subnets, list) or len(subnets) != 1 or not isinstance(subnets[0], dict):
    raise SystemExit(1)
entry = subnets[0]
if not isinstance(entry.get("subnet"), str) or not isinstance(entry.get("gateway"), str):
    raise SystemExit(1)
if entry["subnet"] != sys.argv[1] or entry["gateway"] != sys.argv[2]:
    raise SystemExit(1)
if document[0].get("ipv6_enabled", False) is not False:
    raise SystemExit(1)
PY
    echo "Existing Podman network `$NETWORK_NAME has unexpected subnet or gateway" >&2
    return 1
  fi
  podman run --rm --network "`$NETWORK_NAME" docker.io/library/postgres:18 \
    pg_isready -h 10.101.0.10 -p 5432 >/dev/null
  podman exec nazo-oauth-valkey valkey-cli ping | grep -Fx PONG >/dev/null
  assert_angie_backend_upstream || return 1

  install -d -m 0755 "`$UI_RELEASES"
  mkdir -p "`$DEPLOYMENTS"
  if ! mkdir "`$ACTIVE_DEPLOYMENT" 2>/dev/null; then
    echo "Another deployment transaction is active" >&2
    return 1
  fi
  printf '%s\n' "`$DEPLOYMENT_ID" >"`$ACTIVE_DEPLOYMENT/owner"
  trap 'cleanup' ERR
  previous_image_id=""
  previous_image_name=""
  previous_container_id=""
  if podman container exists "`$CONTAINER_NAME"; then
    previous_image_id="`$(podman inspect "`$CONTAINER_NAME" --format '{{.Image}}')"
    previous_image_name="`$(podman inspect "`$CONTAINER_NAME" --format '{{.ImageName}}')"
    previous_container_id="`$(podman inspect "`$CONTAINER_NAME" --format '{{.Id}}')"
  fi
  previous_ui_kind="missing"
  previous_ui_target=""
  legacy_ui_release=""
  if [ -L "`$UI_PATH" ]; then
    previous_ui_kind="symlink"
    previous_ui_target="`$(readlink "`$UI_PATH")"
  elif [ -d "`$UI_PATH" ]; then
    previous_ui_kind="directory"
    previous_ui_target="`$UI_PATH"
    legacy_ui_release="`$UI_RELEASES/legacy-`$(date +%s)"
  fi
  candidate_container_id=""
  candidate_started="0"
  ui_switched="0"
  keys_mutation_possible="0"
  previous_current_target=""
  if [ -L "`$DEPLOYMENTS/current.json" ]; then
    previous_current_target="`$(readlink "`$DEPLOYMENTS/current.json")"
  fi
  create_keys_snapshot
  save_state
  write_record "preflight"
  trap 'rollback_transaction' ERR
  start_verification_lease
  exec 8>"`$LEASE_LOCK"
  flock -x 8
  trap 'rollback_after_deploy_error' ERR
  assert_pending_lease
  systemctl enable podman-restart.service >/dev/null
  podman update --restart=unless-stopped nazo-oauth-postgres >/dev/null
  podman update --restart=unless-stopped nazo-oauth-valkey >/dev/null
  test "`$(podman inspect nazo-oauth-postgres --format '{{.HostConfig.RestartPolicy.Name}}')" = "unless-stopped"
  test "`$(podman inspect nazo-oauth-valkey --format '{{.HostConfig.RestartPolicy.Name}}')" = "unless-stopped"

  rm -rf "`$UI_RELEASE.tmp"
  install -d -m 0755 "`$UI_RELEASE.tmp"
  tar -xzf "`$REMOTE_UI_ARCHIVE" -C "`$UI_RELEASE.tmp"
  test -s "`$UI_RELEASE.tmp/index.html"
  test -z "`$(find "`$UI_RELEASE.tmp" -type l -print -quit)"
  find "`$UI_RELEASE.tmp" -type d -exec chmod 0755 {} +
  find "`$UI_RELEASE.tmp" -type f -exec chmod 0644 {} +
  if [ -e "`$UI_RELEASE" ]; then
    diff -qr "`$UI_RELEASE" "`$UI_RELEASE.tmp" >/dev/null
    rm -rf "`$UI_RELEASE.tmp"
  else
    mv "`$UI_RELEASE.tmp" "`$UI_RELEASE"
  fi
  test -z "`$(find "`$UI_RELEASE" -type l -print -quit)"
  find "`$UI_RELEASE" -type d -exec chmod 0755 {} +
  find "`$UI_RELEASE" -type f -exec chmod 0644 {} +
  runuser -u "`$ANGIE_WORKER_USER" -- test -r "`$UI_RELEASE/index.html"
  assert_pending_lease
  podman load -i "`$REMOTE_ARCHIVE" >/dev/null
  podman image exists "`$IMAGE"
  actual_image_id="`$(podman image inspect "`$IMAGE" --format '{{.Id}}')"
  test "`$actual_image_id" = "`$EXPECTED_IMAGE_ID"
  actual_revision="`$(podman image inspect "`$IMAGE" --format '{{index .Labels "org.opencontainers.image.revision"}}')"
  test "`$actual_revision" = "`$BACKEND_COMMIT"
  if [ -n "`$previous_image_id" ]; then podman image exists "`$previous_image_id"; fi

  if [ "`$SKIP_MIGRATE" != "1" ]; then
    keys_mutation_possible="1"
    save_state
    podman run --rm --name "`$CONTAINER_NAME-migrate-`$(date +%s)" \
      --network "`$NETWORK_NAME" \
      -v "`$CONFIG_PATH:/app/.env.yaml:ro" \
      -v "`$KEYS_PATH:/var/lib/nazo_oauth/keys:rw" \
      -v "`$AVATARS_PATH:/var/lib/nazo_oauth/avatars:rw" \
      "`$IMAGE" nazoauth migrate
  fi
  assert_pending_lease

  candidate_started="1"
  save_state
  if podman container exists "`$CONTAINER_NAME"; then podman rm -f "`$CONTAINER_NAME" >/dev/null; fi
  run_server "`$IMAGE"
  candidate_container_id="`$(podman inspect "`$CONTAINER_NAME" --format '{{.Id}}')"
  save_state
  test "`$(podman inspect "`$CONTAINER_NAME" --format '{{.HostConfig.RestartPolicy.Name}}')" = "unless-stopped"
  actual_ip="`$(podman inspect "`$CONTAINER_NAME" --format '{{range `$name, `$conf := .NetworkSettings.Networks}}{{println `$conf.IPAddress}}{{end}}' | awk 'NF {print; exit}')"
  test "`$actual_ip" = "`$CONTAINER_IP"
  curl -fsS --max-time 20 "http://`$CONTAINER_IP:8000/health" >/dev/null
  discovery="`$(curl -fsS --max-time 20 "http://`$CONTAINER_IP:8000/.well-known/openid-configuration")"
  python3 -c 'import json,sys; assert json.load(sys.stdin)["issuer"] == sys.argv[1]' "`$EXPECTED_ISSUER" <<<"`$discovery"
  assert_angie_backend_upstream || return 1
  ui_switched="1"
  save_state
  if [ "`$previous_ui_kind" = "directory" ]; then mv -T "`$UI_PATH" "`$legacy_ui_release"; fi
  temporary_link="`$UI_PATH.next-`$BACKEND_COMMIT"
  rm -f "`$temporary_link"
  ln -s "`$UI_RELEASE" "`$temporary_link"
  mv -T "`$temporary_link" "`$UI_PATH"
  runuser -u "`$ANGIE_WORKER_USER" -- test -r "`$UI_PATH/index.html"
  write_record "candidate-verified"
  flock -u 8
  trap - ERR
}

commit_deployment() {
  load_state
  exec 9>"`$LEASE_LOCK"
  flock -x 9
  test -f "`$LEASE_PENDING"
  write_record "deployment-success"
  rm -f "`$CURRENT_LINK_TEMP"
  ln -s "`$RECORD" "`$CURRENT_LINK_TEMP"
  mv -T "`$CURRENT_LINK_TEMP" "`$DEPLOYMENTS/current.json"
  fsync_parent "`$DEPLOYMENTS/current.json"
  mv "`$LEASE_PENDING" "`$LEASE_COMMITTED"
  stop_watchdog
  flock -u 9
  cleanup
}

expire_lease() {
  if [ ! -f "`$STATE_FILE" ]; then return 0; fi
  exec 9>"`$LEASE_LOCK"
  flock -x 9
  if [ ! -f "`$LEASE_PENDING" ]; then return 0; fi
  mv "`$LEASE_PENDING" "`$LEASE_ROLLBACK"
  if rollback; then
    flock -u 9
    cleanup
    return 0
  fi
  flock -u 9
  echo "Verification lease expired and rollback failed; evidence preserved" >&2
  return 1
}

case "`${1:-deploy}" in
  deploy) deploy ;;
  rollback) rollback_transaction ;;
  commit) load_state; commit_deployment ;;
  expire) expire_lease ;;
  *) echo "unknown deployment action" >&2; exit 2 ;;
esac
"@

if ($RenderRemoteScriptPath) {
    Write-Utf8LfFile -Path $RenderRemoteScriptPath -Content $remoteBody
    return
}
Write-Utf8LfFile -Path $localRemoteScript -Content $remoteBody
$remoteStarted = $false
$remoteScriptLiteral = ConvertTo-ShellLiteral $remoteScript
$deployCommand = "bash $remoteScriptLiteral deploy"
$commitCommand = "bash $remoteScriptLiteral commit"
$rollbackCommand = "if [ -f $remoteScriptLiteral ]; then bash $remoteScriptLiteral rollback; fi"
try {
    Invoke-ScpChecked @($localRemoteScript, "${RemoteHost}:$remoteScript")
    $remoteStarted = $true
    Invoke-SshChecked @($deployCommand)

    $health = Invoke-WebRequest -Uri $HealthUrl -UseBasicParsing -TimeoutSec 20
    if ($health.StatusCode -ne 200) { throw "Health probe failed: HTTP $($health.StatusCode)" }
    $discovery = Invoke-WebRequest -Uri $DiscoveryUrl -UseBasicParsing -TimeoutSec 20
    if ($discovery.StatusCode -ne 200) { throw "Discovery probe failed: HTTP $($discovery.StatusCode)" }
    $metadata = $discovery.Content | ConvertFrom-Json
    if ($metadata.issuer -ne $ExpectedIssuer) {
        throw "Unexpected issuer in discovery document: $($metadata.issuer)"
    }
    $ui = Invoke-WebRequest -Uri $UiUrl -UseBasicParsing -TimeoutSec 20
    if ($ui.StatusCode -ne 200 -or [string]::IsNullOrWhiteSpace($ui.Content)) {
        throw "Public UI probe failed: HTTP $($ui.StatusCode)"
    }
    $assetMatch = [regex]::Match(
        $ui.Content,
        '(?:src|href)=["''](?<path>/ui/assets/[^"''?#]+(?:[?#][^"'']*)?)["'']',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    if (-not $assetMatch.Success) {
        throw "Public UI probe did not find a same-origin /ui/assets reference"
    }
    $assetUrl = [Uri]::new([Uri]$UiUrl, $assetMatch.Groups['path'].Value)
    $asset = Invoke-WebRequest -Uri $assetUrl -UseBasicParsing -TimeoutSec 20
    if ($asset.StatusCode -ne 200 -or [string]::IsNullOrWhiteSpace($asset.Content)) {
        throw "Public UI asset probe failed: HTTP $($asset.StatusCode)"
    }

    Invoke-SshChecked @($commitCommand)
    $remoteStarted = $false
    Write-Host "Deployment verified: $image deployment-success"
}
catch {
    if ($remoteStarted) {
        & ssh @SshOptions $RemoteHost $rollbackCommand
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Automatic rollback command failed; inspect $RemoteHost immediately"
        }
    }
    throw
}
finally {
    Remove-Item -LiteralPath $localRemoteScript, $uiArchive, $archive -Force -ErrorAction SilentlyContinue
}
