param(
    [Parameter(Mandatory = $true)]
    [string]$RemoteHost,
    [Parameter(Mandatory = $true)]
    [string]$BackendCommit,
    [Parameter(Mandatory = $true)]
    [string]$FrontendCommit,
    [string]$LocalFrontendWorktree = "",
    [string]$LocalBackendWorktree = ".",
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
    [string]$RemoteUiPath = "/usr/local/angie/html/auth/ui",
    [string]$RemoteUiReleasesRoot = "/usr/local/angie/html/auth-releases",
    [string]$OidfPublicSeedArtifactDirectory = "",
    [string]$OidfPublicSeedArtifactArchive = "",
    [string]$OidfPublicSeedWorkflowRunId = "",
    [string]$OidfPublicSeedArtifactId = "",
    [string]$OidfPublicSeedArtifactDigest = "",
    [string]$RemoteOidfMtlsCaPath = "/usr/local/angie/conf/oidf-mtls-ca.crt",
    [string]$RemoteAngieOidfConfigPath = "/usr/local/angie/conf/conf.d/auth.nazo.run.conf",
    [string]$AngieServiceName = "nginx.service",
    [string]$AngieWorkerUser = "www",
    [string]$RemoteDeploymentRoot = "/opt/nazo-oauth",
    [string]$LocalUiDist = "",
    [string]$PublishPort = "",
    [string]$HealthUrl = "https://auth.nazo.run/health",
    [string]$DiscoveryUrl = "https://auth.nazo.run/.well-known/openid-configuration",
    [string]$UiUrl = "https://auth.nazo.run/ui/auth",
    [string]$ExpectedIssuer = "https://auth.nazo.run",
    [ValidateRange(1, 3600)]
    [int]$VerificationLeaseSeconds = 120,
    [string]$RenderRemoteScriptPath = "",
    [string]$RenderRemoteTempDir = "/tmp/nazo-oauth-deploy.render",
    [switch]$SkipBuild,
    [switch]$SkipFrontendBuild,
    [switch]$SkipMigrate
)

$ErrorActionPreference = "Stop"
$ExpectedBackendRemote = "https://github.com/nazozero/NazoAuth"
$ExpectedBackendBranch = "codex/modular-workspace-architecture"
$ExpectedFrontendRemote = "https://github.com/nazozero/NazoAuthWeb"
$ExpectedFrontendBranch = "codex/modular-workspace-architecture"

if ($RemoteHost.StartsWith('-') -or
    $RemoteHost -notmatch '^(?:[A-Za-z0-9_][A-Za-z0-9._-]*@)?[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$') {
    throw "RemoteHost must be a safe SSH host alias, hostname, or user@host"
}
if ($RemoteUiPath -notmatch '^/' -or $RemoteUiReleasesRoot -notmatch '^/') {
    throw "RemoteUiPath and RemoteUiReleasesRoot must be absolute Linux paths"
}
if ($RemoteOidfMtlsCaPath -notmatch '^/' -or $RemoteOidfMtlsCaPath -eq '/' -or
    $RemoteOidfMtlsCaPath.Contains("`n") -or $RemoteOidfMtlsCaPath.Contains("`r")) {
    throw "RemoteOidfMtlsCaPath must be a safe absolute non-root Linux path"
}
if ($RemoteAngieOidfConfigPath -notmatch '^/' -or $RemoteAngieOidfConfigPath -eq '/' -or
    $RemoteAngieOidfConfigPath.Contains("`n") -or $RemoteAngieOidfConfigPath.Contains("`r")) {
    throw "RemoteAngieOidfConfigPath must be a safe absolute non-root Linux path"
}
if ($AngieServiceName -notmatch '^[A-Za-z0-9_.@-]+$') {
    throw "AngieServiceName must be a safe systemd unit name"
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
    $status = & git -C $root status --porcelain=v1 --untracked-files=all
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
    $directories = @(
        Get-ChildItem -LiteralPath $siblingRoot -Directory -Force |
            Where-Object { $_.Name -eq "NazoAuthWeb" -or $_.Name -like "NazoAuthWeb-*" } |
            Sort-Object FullName
    )
    $qualified = [System.Collections.Generic.List[string]]::new()
    $rejected = [System.Collections.Generic.List[string]]::new()
    foreach ($directory in $directories) {
        try {
            $qualified.Add((Assert-FrontendWorktree -Worktree $directory.FullName -ExpectedCommit $ExpectedCommit))
        }
        catch {
            $rejected.Add("$($directory.FullName): $($_.Exception.Message)")
        }
    }
    if ($qualified.Count -eq 1) {
        return $qualified[0]
    }
    if ($qualified.Count -gt 1) {
        throw "Frontend worktree discovery is ambiguous; qualified candidates: $($qualified -join ', '). Pass LocalFrontendWorktree explicitly."
    }
    $details = if ($rejected.Count -gt 0) { " Rejected candidates: $($rejected -join '; ')" } else { "" }
    throw "Unable to discover a unique synchronized sibling NazoAuthWeb worktree under $siblingRoot.$details Pass LocalFrontendWorktree explicitly."
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
$oidfCaEnabledValue = "0"
$oidfCaSha256 = ""
$oidfManifestSha256 = ""
$oidfArtifactFiles = @()
$verifiedArtifactDirectory = ""
$localOidfCaValidator = Join-Path $LocalBackendWorktree "scripts/oidf_mtls_ca_bundle.py"
if ($OidfPublicSeedArtifactDirectory -or $OidfPublicSeedArtifactArchive) {
    if (-not $RenderRemoteScriptPath) {
        if (-not $OidfPublicSeedArtifactArchive -or
            $OidfPublicSeedWorkflowRunId -notmatch '^[1-9][0-9]*$' -or
            $OidfPublicSeedArtifactId -notmatch '^[1-9][0-9]*$' -or
            $OidfPublicSeedArtifactDigest -notmatch '^sha256:[0-9a-f]{64}$') {
            throw "Real OIDF CA deployment requires artifact archive, workflow run ID, artifact ID, and SHA-256 digest"
        }
        $archive = Get-Item -LiteralPath $OidfPublicSeedArtifactArchive -Force -ErrorAction Stop
        if ($archive.PSIsContainer -or ($archive.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "OIDF public seed artifact archive must be a regular non-symlink file"
        }
        $artifactMetadata = Get-GitHubApiJson "/repos/nazozero/NazoAuth/actions/artifacts/$OidfPublicSeedArtifactId"
        $runMetadata = Get-GitHubApiJson "/repos/nazozero/NazoAuth/actions/runs/$OidfPublicSeedWorkflowRunId"
        if ([string]$artifactMetadata.name -cne "oidf-public-plan-configs" -or
            [bool]$artifactMetadata.expired -or
            [long]$artifactMetadata.size_in_bytes -le 0 -or
            [long]$artifactMetadata.size_in_bytes -gt 16777216 -or
            [string]$artifactMetadata.digest -cne $OidfPublicSeedArtifactDigest -or
            [string]$artifactMetadata.workflow_run.id -cne $OidfPublicSeedWorkflowRunId -or
            [string]$artifactMetadata.workflow_run.head_sha -cne $BackendCommit -or
            [string]$runMetadata.head_sha -cne $BackendCommit -or
            [string]$runMetadata.head_branch -cne $ExpectedBackendBranch -or
            [string]$runMetadata.conclusion -cne "success") {
            throw "OIDF public seed artifact metadata does not match the successful exact-head workflow run"
        }
        if ($archive.Length -ne [long]$artifactMetadata.size_in_bytes) {
            throw "OIDF public seed artifact archive size does not match GitHub metadata"
        }
        $archiveSha256 = (Get-FileHash -LiteralPath $archive.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        if ("sha256:$archiveSha256" -cne $OidfPublicSeedArtifactDigest) {
            throw "OIDF public seed artifact archive digest does not match GitHub metadata"
        }
        $verifiedArtifactDirectory = Join-Path ([IO.Path]::GetTempPath()) (
            "nazo-oidf-public-artifact-" + [Guid]::NewGuid().ToString("N")
        )
        [IO.Compression.ZipFile]::ExtractToDirectory($archive.FullName, $verifiedArtifactDirectory)
        $OidfPublicSeedArtifactDirectory = $verifiedArtifactDirectory
    }
    elseif (-not $OidfPublicSeedArtifactDirectory) {
        throw "Render-only OIDF CA validation requires OidfPublicSeedArtifactDirectory"
    }
    if (-not (Test-Path -LiteralPath $localOidfCaValidator -PathType Leaf)) {
        throw "Backend commit does not contain scripts/oidf_mtls_ca_bundle.py"
    }
    $OidfPublicSeedArtifactDirectory = [System.IO.Path]::GetFullPath(
        $OidfPublicSeedArtifactDirectory
    )
    Invoke-Checked python @(
        $localOidfCaValidator,
        "verify",
        "--artifact-directory",
        $OidfPublicSeedArtifactDirectory,
        "--expected-source-commit",
        $BackendCommit
    )
    $localOidfCaBundle = Join-Path $OidfPublicSeedArtifactDirectory "oidf-mtls-ca-bundle.pem"
    $oidfCaSha256 = (Get-FileHash -LiteralPath $localOidfCaBundle -Algorithm SHA256).Hash.ToLowerInvariant()
    $localOidfManifest = Join-Path $OidfPublicSeedArtifactDirectory "oidf-public-plan-configs.manifest.json"
    $oidfManifestSha256 = (Get-FileHash -LiteralPath $localOidfManifest -Algorithm SHA256).Hash.ToLowerInvariant()
    $oidfArtifactFiles = @(Get-ChildItem -LiteralPath $OidfPublicSeedArtifactDirectory -File)
    $oidfCaEnabledValue = "1"
}
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
$archive = Join-Path ([System.IO.Path]::GetTempPath()) "nazo-oauth-server-$safeTag.tar"
$uiArchive = Join-Path ([System.IO.Path]::GetTempPath()) "nazo-oauth-web-$safeTag.tar.gz"
$localRemoteScript = Join-Path ([System.IO.Path]::GetTempPath()) "nazo-oauth-deploy-$safeTag.sh"

Write-Host "Staging $image ($BackendCommit / $FrontendCommit) on $RemoteHost"

$expectedImageId = "0" * 64
if ($RenderRemoteScriptPath) {
    $remoteTempDir = $RenderRemoteTempDir
}
else {
    $backendBuildContext = Export-GitCommit -Worktree $LocalBackendWorktree -Commit $BackendCommit -Label "backend-source"
    try {
        Invoke-Checked docker @(
            "build", "-f", (Join-Path $backendBuildContext "Containerfile"),
            "--label", "org.opencontainers.image.revision=$BackendCommit",
            "-t", $image, $backendBuildContext
        )
    }
    finally {
        Remove-Item -LiteralPath $backendBuildContext -Recurse -Force -ErrorAction SilentlyContinue
    }
    $LocalBackendWorktree = Assert-CleanGitCommit -Worktree $LocalBackendWorktree -ExpectedCommit $BackendCommit -Label "Backend after build"
    $localDescriptorId = Get-CommandOutput docker @("image", "inspect", $image, "--format", "{{.Id}}")
    if ($localDescriptorId -notmatch '^sha256:[0-9a-f]{64}$') {
        throw "Docker returned an invalid immutable image descriptor: $localDescriptorId"
    }
    Remove-Item -LiteralPath $archive, $uiArchive -Force -ErrorAction SilentlyContinue
    Invoke-Checked docker @("save", $image, "-o", $archive)
    $expectedImageId = Get-ArchiveImageConfigId -Archive $archive -ExpectedTag $image
    Invoke-Checked tar @("-C", $LocalUiDist, "-czf", $uiArchive, ".")
    $remoteTempDir = Get-CommandOutput ssh $RemoteHost @("mktemp", "-d", "/tmp/nazo-oauth-deploy.XXXXXX")
}
$remoteArchive = "$remoteTempDir/nazo-oauth-server-$safeTag.tar"
$remoteUiArchive = "$remoteTempDir/nazo-oauth-web-$safeTag.tar.gz"
$remoteScript = "$remoteTempDir/deploy.sh"
$remoteState = "$remoteTempDir/state.json"
$remoteOidfArtifactDir = "$remoteTempDir/oidf-public-plan-configs"
$remoteOidfCaValidator = "$remoteTempDir/oidf_mtls_ca_bundle.py"
$remoteOidfCaBackup = "$remoteTempDir/oidf-mtls-ca.previous"
$remoteAngieConfigBackup = "$remoteTempDir/angie-oidf-config.previous"
if (-not $RenderRemoteScriptPath) {
    Invoke-Checked scp $archive "${RemoteHost}:$remoteArchive"
    Invoke-Checked scp $uiArchive "${RemoteHost}:$remoteUiArchive"
    if ($oidfCaEnabledValue -eq "1") {
        Invoke-Checked ssh $RemoteHost @("install", "-d", "-m", "0700", $remoteOidfArtifactDir)
        $oidfScpArguments = @($oidfArtifactFiles.FullName) + "${RemoteHost}:$remoteOidfArtifactDir/"
        Invoke-Checked scp $oidfScpArguments
        Invoke-Checked scp $localOidfCaValidator "${RemoteHost}:$remoteOidfCaValidator"
    }
    if ($verifiedArtifactDirectory) {
        $resolvedArtifactDirectory = [IO.Path]::GetFullPath($verifiedArtifactDirectory)
        $resolvedTempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
            [IO.Path]::DirectorySeparatorChar
        )
        if ([IO.Path]::GetDirectoryName($resolvedArtifactDirectory) -cne $resolvedTempRoot -or
            [IO.Path]::GetFileName($resolvedArtifactDirectory) -notmatch '^nazo-oidf-public-artifact-[0-9a-f]{32}$') {
            throw "Refusing to remove unexpected OIDF artifact staging path: $resolvedArtifactDirectory"
        }
        Remove-Item -LiteralPath $resolvedArtifactDirectory -Recurse -Force
    }
}

$skipMigrateValue = if ($SkipMigrate) { "1" } else { "0" }
$deploymentId = [guid]::NewGuid().ToString("N")
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
UI_PATH=$(ConvertTo-ShellLiteral $RemoteUiPath)
UI_RELEASES=$(ConvertTo-ShellLiteral $RemoteUiReleasesRoot)
ANGIE_WORKER_USER=$(ConvertTo-ShellLiteral $AngieWorkerUser)
DEPLOYMENT_ROOT=$(ConvertTo-ShellLiteral $RemoteDeploymentRoot)
PUBLISH_PORT=$(ConvertTo-ShellLiteral $PublishPort)
EXPECTED_ISSUER=$(ConvertTo-ShellLiteral $ExpectedIssuer)
EXPECTED_IMAGE_ID=$(ConvertTo-ShellLiteral $expectedImageId)
SKIP_MIGRATE=$(ConvertTo-ShellLiteral $skipMigrateValue)
VERIFICATION_LEASE_SECONDS=$(ConvertTo-ShellLiteral $VerificationLeaseSeconds)
OIDF_CA_ENABLED=$(ConvertTo-ShellLiteral $oidfCaEnabledValue)
OIDF_CA_SHA256=$(ConvertTo-ShellLiteral $oidfCaSha256)
OIDF_MANIFEST_SHA256=$(ConvertTo-ShellLiteral $oidfManifestSha256)
OIDF_CA_ARTIFACT_DIR=$(ConvertTo-ShellLiteral $remoteOidfArtifactDir)
OIDF_CA_VALIDATOR=$(ConvertTo-ShellLiteral $remoteOidfCaValidator)
OIDF_CA_BACKUP=$(ConvertTo-ShellLiteral $remoteOidfCaBackup)
OIDF_CA_TARGET=$(ConvertTo-ShellLiteral $RemoteOidfMtlsCaPath)
ANGIE_OIDF_CONFIG=$(ConvertTo-ShellLiteral $RemoteAngieOidfConfigPath)
ANGIE_CONFIG_BACKUP=$(ConvertTo-ShellLiteral $remoteAngieConfigBackup)
ANGIE_SERVICE=$(ConvertTo-ShellLiteral $AngieServiceName)
OIDF_WORKFLOW_RUN_ID=$(ConvertTo-ShellLiteral $OidfPublicSeedWorkflowRunId)
OIDF_ARTIFACT_ID=$(ConvertTo-ShellLiteral $OidfPublicSeedArtifactId)
OIDF_ARTIFACT_DIGEST=$(ConvertTo-ShellLiteral $OidfPublicSeedArtifactDigest)

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

run_server() {
  local selected_image="`$1"
  local publish_args=()
  if [ -n "`$PUBLISH_PORT" ]; then publish_args=(-p "`$PUBLISH_PORT"); fi
  podman run -d --name "`$CONTAINER_NAME" \
    --restart=unless-stopped \
    --network "`$NETWORK_NAME" --ip "`$CONTAINER_IP" \
    "`${publish_args[@]}" \
    -v "`$CONFIG_PATH:/app/.env.yaml:ro" \
    -v "`$KEYS_PATH:/var/lib/nazo_oauth/keys:rw" \
    -v "`$AVATARS_PATH:/var/lib/nazo_oauth/avatars:rw" \
    "`$selected_image" nazo-oauth-server >/dev/null
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

secure_angie_oidf_config_sha256() {
  python3 - "`$ANGIE_OIDF_CONFIG" <<'PY'
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
        raise SystemExit("Angie OIDF config must be a regular file")
    if os.name == "posix":
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise SystemExit("Angie OIDF config must be root-owned and not group/world-writable")
        for parent in (path.parent, *path.parents):
            parent_metadata = os.stat(parent, follow_symlinks=False)
            if (
                not stat.S_ISDIR(parent_metadata.st_mode)
                or parent_metadata.st_uid != 0
                or parent_metadata.st_mode & 0o022
            ):
                raise SystemExit(
                    "Angie OIDF config parent directories must be root-owned and not group/world-writable"
                )
    with os.fdopen(descriptor, "rb", closefd=False) as source:
        digest = hashlib.sha256(source.read()).hexdigest()
finally:
    os.close(descriptor)
print(digest)
PY
}

validate_oidf_ca_artifact() {
  [ "`$OIDF_CA_ENABLED" = "1" ] || return 0
  test -f "`$OIDF_CA_VALIDATOR" || return 1
  python3 "`$OIDF_CA_VALIDATOR" verify \
    --artifact-directory "`$OIDF_CA_ARTIFACT_DIR" \
    --expected-source-commit "`$BACKEND_COMMIT" || return 1
  require_sha256 "`$OIDF_CA_ARTIFACT_DIR/oidf-mtls-ca-bundle.pem" "`$OIDF_CA_SHA256" "OIDF CA bundle" || return 1
  require_sha256 "`$OIDF_CA_ARTIFACT_DIR/oidf-public-plan-configs.manifest.json" "`$OIDF_MANIFEST_SHA256" "OIDF manifest" || return 1
}

assert_angie_oidf_ca_target() {
  [ "`$OIDF_CA_ENABLED" = "1" ] || return 0
  local angie_config validated_config_sha256
  test -f "`$ANGIE_OIDF_CONFIG" || return 1
  test ! -L "`$ANGIE_OIDF_CONFIG" || return 1
  if ! angie_config="`$(angie -T 2>&1)"; then
    echo "Angie configuration dump failed" >&2
    return 1
  fi
  grep -F "# configuration file `$ANGIE_OIDF_CONFIG:" <<<"`$angie_config" >/dev/null || {
    echo "`$ANGIE_OIDF_CONFIG is not present in the active Angie configuration" >&2
    return 1
  }
  if ! validated_config_sha256="`$(OIDF_EXPECTED_CA_TARGET="`$OIDF_CA_TARGET" python3 - "`$ANGIE_OIDF_CONFIG" <<'PY'
import hashlib
import os
import pathlib
import stat
import sys


class ConfigError(Exception):
    pass


def directives(source: str):
    tokens: list[str] = []
    token: list[str] = []
    quote: str | None = None
    escaped = False
    comment = False

    def flush_token() -> None:
        if token:
            tokens.append("".join(token))
            token.clear()

    for character in source:
        if comment:
            if character in "\r\n":
                comment = False
            continue
        if escaped:
            token.append(character)
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if quote is not None:
            if character == quote:
                quote = None
            else:
                token.append(character)
            continue
        if character in "'\"":
            quote = character
        elif character == "#":
            flush_token()
            comment = True
        elif character.isspace():
            flush_token()
        elif character == ";":
            flush_token()
            if not tokens:
                raise ConfigError("empty directive")
            yield tuple(tokens)
            tokens.clear()
        elif character == "{":
            flush_token()
            if tokens and tokens[0] == "include":
                raise ConfigError("include directives are not permitted")
            tokens.clear()
        elif character == "}":
            flush_token()
            if tokens:
                raise ConfigError("unterminated directive before block end")
        else:
            token.append(character)
    if quote is not None or escaped:
        raise ConfigError("unterminated quote or escape")
    flush_token()
    if tokens:
        raise ConfigError("unterminated directive at end of file")


config_path = pathlib.Path(sys.argv[1])
target_path = os.environ["OIDF_EXPECTED_CA_TARGET"]
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(config_path, flags)
try:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"{config_path} must be a regular file")
    if os.name == "posix":
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise SystemExit(
                f"{config_path} must be root-owned and not group/world-writable"
            )
        for parent in (config_path.parent, *config_path.parents):
            parent_metadata = os.stat(parent, follow_symlinks=False)
            if (
                not stat.S_ISDIR(parent_metadata.st_mode)
                or parent_metadata.st_uid != 0
                or parent_metadata.st_mode & 0o022
            ):
                raise SystemExit(
                    f"{config_path} parent directories must be root-owned and not group/world-writable"
                )
    with os.fdopen(descriptor, "rb", closefd=False) as config_file:
        raw_source = config_file.read()
finally:
    os.close(descriptor)
source = raw_source.decode("utf-8")
if "\x00" in source:
    raise SystemExit(f"{config_path} contains a NUL byte")

ca_paths: list[str] = []
verify_sources: list[str] = []
certificate_sources: list[str] = []
try:
    for directive in directives(source):
        name = directive[0]
        if any(token.upper() == "SUCCESS" for token in directive):
            raise ConfigError("certificate verification must not be overridden with SUCCESS")
        if name == "include":
            raise ConfigError("include directives are not permitted")
        if name == "ssl_client_certificate":
            if len(directive) != 2:
                raise ConfigError("ssl_client_certificate must have exactly one argument")
            ca_paths.append(directive[1])
        if name == "proxy_set_header" and len(directive) >= 2:
            header = directive[1].lower()
            if header == "x-ssl-client-verify":
                if len(directive) != 3:
                    raise ConfigError("X-SSL-Client-Verify must have exactly one value")
                verify_sources.append(directive[2])
            if header == "x-ssl-client-cert":
                if len(directive) != 3:
                    raise ConfigError("X-SSL-Client-Cert must have exactly one value")
                certificate_sources.append(directive[2])
except ConfigError as error:
    raise SystemExit(f"unsafe Angie OIDF configuration: {error}") from error

if not ca_paths or any(path != target_path for path in ca_paths):
    raise SystemExit(
        f"ssl_client_certificate must exclusively reference {target_path}"
    )
if verify_sources != ["`$ssl_client_verify"]:
    raise SystemExit(
        "X-SSL-Client-Verify must be set exactly once from ssl_client_verify"
    )
if certificate_sources != ["`$ssl_client_escaped_cert"]:
    raise SystemExit(
        "X-SSL-Client-Cert must be set exactly once from ssl_client_escaped_cert"
    )
print(hashlib.sha256(raw_source).hexdigest())
PY
)"; then
    return 1
  fi
  if [[ ! "`$validated_config_sha256" =~ ^[0-9a-f]{64}`$ ]]; then
    echo "Angie OIDF configuration validator returned an invalid digest" >&2
    return 1
  fi
  angie_oidf_config_sha256="`$validated_config_sha256"
}

assert_angie_oidf_config_unchanged() {
  [ "`$OIDF_CA_ENABLED" = "1" ] || return 0
  [ -n "`${angie_oidf_config_sha256:-}" ] || return 1
  local current_digest
  if ! current_digest="`$(secure_angie_oidf_config_sha256)"; then
    return 1
  fi
  if [ "`$current_digest" != "`$angie_oidf_config_sha256" ]; then
    echo "Angie OIDF configuration changed during deployment" >&2
    return 1
  fi
}

restore_angie_oidf_config() {
  local current_digest target_dir temporary
  require_sha256 "`$ANGIE_CONFIG_BACKUP" "`$angie_oidf_config_sha256" "Angie OIDF configuration backup" || return 1
  current_digest="`$(secure_angie_oidf_config_sha256 2>/dev/null || true)"
  if [ "`$current_digest" != "`$angie_oidf_config_sha256" ]; then
    target_dir="`$(dirname "`$ANGIE_OIDF_CONFIG")"
    temporary="`$(mktemp "`$target_dir/.angie-oidf-config.rollback.XXXXXX")" || return 1
    cp --preserve=mode,ownership,timestamps -- "`$ANGIE_CONFIG_BACKUP" "`$temporary" || return 1
    require_sha256 "`$temporary" "`$angie_oidf_config_sha256" "staged Angie OIDF configuration rollback" || return 1
    mv -f "`$temporary" "`$ANGIE_OIDF_CONFIG" || return 1
    fsync_parent "`$ANGIE_OIDF_CONFIG" || return 1
  fi
  assert_angie_oidf_ca_target || return 1
  assert_angie_oidf_config_unchanged || return 1
}

reload_angie_and_wait() {
  local before_workers after_workers deadline master_pid new_worker old_worker_remaining pid
  master_pid="`$(systemctl show --property MainPID --value "`$ANGIE_SERVICE")" || return 1
  [[ "`$master_pid" =~ ^[1-9][0-9]*`$ ]] || return 1
  before_workers="`$(pgrep -P "`$master_pid" -f 'worker process' | sort -n || true)"
  systemctl reload "`$ANGIE_SERVICE" || return 1
  deadline=`$((SECONDS + `${ANGIE_RELOAD_WAIT_SECONDS:-15}))
  while [ "`$SECONDS" -lt "`$deadline" ]; do
    after_workers="`$(pgrep -P "`$master_pid" -f 'worker process' | sort -n || true)"
    new_worker="0"
    for pid in `$after_workers; do
      if ! grep -Fx "`$pid" <<<"`$before_workers" >/dev/null; then
        new_worker="1"
        break
      fi
    done
    old_worker_remaining="0"
    for pid in `$before_workers; do
      if grep -Fx "`$pid" <<<"`$after_workers" >/dev/null; then
        old_worker_remaining="1"
        break
      fi
    done
    if [ "`$new_worker" = "1" ] && [ "`$old_worker_remaining" = "0" ]; then
      return 0
    fi
    sleep 0.1
  done
  echo "Angie workers did not rotate after reload" >&2
  return 1
}

install_oidf_ca() {
  [ "`$OIDF_CA_ENABLED" = "1" ] || return 0
  validate_oidf_ca_artifact || return 1
  assert_angie_oidf_ca_target || return 1
  local target_dir temporary
  target_dir="`$(dirname "`$OIDF_CA_TARGET")"
  install -d -m 0755 "`$target_dir" || return 1
  temporary="`$(mktemp "`$target_dir/.oidf-mtls-ca.XXXXXX")" || return 1
  install -m 0644 "`$OIDF_CA_ARTIFACT_DIR/oidf-mtls-ca-bundle.pem" "`$temporary" || return 1
  python3 "`$OIDF_CA_VALIDATOR" verify --bundle "`$temporary" || return 1
  require_sha256 "`$temporary" "`$OIDF_CA_SHA256" "staged OIDF CA bundle" || return 1
  assert_angie_oidf_config_unchanged || return 1
  ca_switched="1"
  save_state || return 1
  mv -f "`$temporary" "`$OIDF_CA_TARGET" || return 1
  fsync_parent "`$OIDF_CA_TARGET" || return 1
  assert_angie_oidf_config_unchanged || return 1
  angie -t || return 1
  assert_angie_oidf_config_unchanged || return 1
  reload_angie_and_wait || return 1
  assert_angie_oidf_config_unchanged || return 1
  python3 "`$OIDF_CA_VALIDATOR" verify --bundle "`$OIDF_CA_TARGET" || return 1
  require_sha256 "`$OIDF_CA_TARGET" "`$OIDF_CA_SHA256" "installed OIDF CA bundle" || return 1
}

restore_oidf_ca() {
  [ "`${ca_switched:-0}" = "1" ] || return 0
  local target_dir temporary
  target_dir="`$(dirname "`$OIDF_CA_TARGET")"
  if [ "`$previous_ca_kind" = "file" ]; then
    test -f "`$OIDF_CA_BACKUP" || return 1
    require_sha256 "`$OIDF_CA_BACKUP" "`$previous_ca_sha256" "OIDF CA rollback backup" || return 1
    temporary="`$(mktemp "`$target_dir/.oidf-mtls-ca.rollback.XXXXXX")" || return 1
    cp --preserve=mode,ownership,timestamps -- "`$OIDF_CA_BACKUP" "`$temporary" || return 1
    mv -f "`$temporary" "`$OIDF_CA_TARGET" || return 1
  elif [ "`$previous_ca_kind" = "missing" ]; then
    rm -f "`$OIDF_CA_TARGET" || return 1
  else
    echo "Invalid previous OIDF CA state: `$previous_ca_kind" >&2
    return 1
  fi
  fsync_parent "`$OIDF_CA_TARGET" || return 1
  restore_angie_oidf_config || return 1
  angie -t || return 1
  assert_angie_oidf_config_unchanged || return 1
  reload_angie_and_wait || return 1
  assert_angie_oidf_config_unchanged || return 1
  if [ "`$previous_ca_kind" = "file" ]; then
    cmp -s "`$OIDF_CA_BACKUP" "`$OIDF_CA_TARGET" || return 1
    require_sha256 "`$OIDF_CA_TARGET" "`$previous_ca_sha256" "restored OIDF CA bundle" || return 1
  else
    test ! -e "`$OIDF_CA_TARGET" || return 1
  fi
}

write_record() {
  local status="`$1"
  python3 - "`$RECORD" "`$status" "`$BACKEND_COMMIT" "`$FRONTEND_COMMIT" \
    "`$DEPLOYMENT_ID" "`$IMAGE" "`$EXPECTED_IMAGE_ID" "`$FRONTEND_ARTIFACT_SHA256" \
    "`${previous_image_id:-}" "`${previous_image_name:-}" \
    "`${previous_container_id:-}" "`${previous_ui_target:-}" "`${candidate_container_id:-}" \
    "`$UI_RELEASE" "`$OIDF_CA_ENABLED" "`$OIDF_CA_SHA256" "`$OIDF_MANIFEST_SHA256" \
    "`$OIDF_WORKFLOW_RUN_ID" "`$OIDF_ARTIFACT_ID" "`$OIDF_ARTIFACT_DIGEST" \
    "`${previous_ca_sha256:-}" <<'PY'
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
    "oidf_ca_installed": sys.argv[15] == "1",
    "oidf_source_commit": sys.argv[3] if sys.argv[15] == "1" else "",
    "oidf_ca_sha256": sys.argv[16],
    "oidf_manifest_sha256": sys.argv[17],
    "oidf_workflow_run_id": sys.argv[18],
    "oidf_artifact_id": sys.argv[19],
    "oidf_artifact_digest": sys.argv[20],
    "oidf_previous_ca_sha256": sys.argv[21],
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
    "`$candidate_started" "`$ui_switched" "`$previous_ca_kind" "`$previous_ca_sha256" "`$ca_switched" \
    "`${angie_oidf_config_sha256:-}" <<'PY'
import json, os, sys
keys = (
    "deployment_id", "previous_image_id", "previous_image_name",
    "previous_container_id", "previous_ui_kind", "previous_ui_target",
    "legacy_ui_release", "candidate_container_id", "previous_current_target",
    "candidate_started", "ui_switched", "previous_ca_kind", "previous_ca_sha256", "ca_switched",
    "angie_oidf_config_sha256",
)
payload = dict(zip(keys, sys.argv[2:], strict=True))
payload["schema"] = 2
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
import json, pathlib, re, shlex, sys
path = pathlib.Path(sys.argv[1])
try:
    payload = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"invalid deployment state: {error}")
keys = {
    "schema", "deployment_id", "previous_image_id", "previous_image_name",
    "previous_container_id", "previous_ui_kind", "previous_ui_target",
    "legacy_ui_release", "candidate_container_id", "previous_current_target",
    "candidate_started", "ui_switched", "previous_ca_kind", "previous_ca_sha256", "ca_switched",
    "angie_oidf_config_sha256",
}
if set(payload) != keys or payload.get("schema") != 2:
    raise SystemExit("invalid deployment state schema")
if payload.get("deployment_id") != sys.argv[2]:
    raise SystemExit("deployment state owner mismatch")
for key in keys - {"schema"}:
    if not isinstance(payload[key], str) or "\0" in payload[key] or "\n" in payload[key]:
        raise SystemExit(f"invalid deployment state field: {key}")
if payload["previous_ui_kind"] not in {"missing", "symlink", "directory"}:
    raise SystemExit("invalid previous_ui_kind")
if payload["previous_ca_kind"] not in {"disabled", "missing", "file"}:
    raise SystemExit("invalid previous_ca_kind")
if payload["previous_ca_kind"] == "file":
    if not re.fullmatch(r"[0-9a-f]{64}", payload["previous_ca_sha256"]):
        raise SystemExit("invalid previous_ca_sha256")
elif payload["previous_ca_sha256"]:
    raise SystemExit("unexpected previous_ca_sha256")
if payload["previous_ca_kind"] == "disabled":
    if payload["angie_oidf_config_sha256"]:
        raise SystemExit("unexpected angie_oidf_config_sha256")
elif not re.fullmatch(r"[0-9a-f]{64}", payload["angie_oidf_config_sha256"]):
    raise SystemExit("invalid angie_oidf_config_sha256")
if any(payload[key] not in {"0", "1"} for key in ("candidate_started", "ui_switched", "ca_switched")):
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
  local image_failed=0 ui_failed=0 ca_failed=0 pointer_failed=0 restored_image
  if [ "`$candidate_started" = "1" ]; then
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
  if [ "`${ca_switched:-0}" = "1" ] && ! restore_oidf_ca; then
    ca_failed=1
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
  if [ "`$image_failed" != "0" ] || [ "`$ui_failed" != "0" ] || [ "`$ca_failed" != "0" ] || [ "`$pointer_failed" != "0" ]; then
    write_record "rollback-failed" || true
    return 1
  fi
  write_record "rolled-back"
}

cleanup() {
  rm -f "`$REMOTE_ARCHIVE" "`$REMOTE_UI_ARCHIVE" "`$REMOTE_SCRIPT" "`$STATE_FILE" \
    "`$WATCHDOG_PID_FILE" "`$LEASE_PENDING" "`$LEASE_COMMITTED" "`$LEASE_ROLLBACK" \
    "`$CURRENT_LINK_TEMP" "`$OIDF_CA_VALIDATOR" "`$OIDF_CA_BACKUP" "`$ANGIE_CONFIG_BACKUP"
  rm -rf "`$UI_RELEASE.tmp" "`$OIDF_CA_ARTIFACT_DIR"
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
  validate_oidf_ca_artifact || return 1
  assert_angie_oidf_ca_target || return 1

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
  previous_ca_kind="disabled"
  previous_ca_sha256=""
  ca_switched="0"
  if [ "`$OIDF_CA_ENABLED" = "1" ]; then
    cp --preserve=mode,ownership,timestamps -- "`$ANGIE_OIDF_CONFIG" "`$ANGIE_CONFIG_BACKUP" || return 1
    require_sha256 "`$ANGIE_CONFIG_BACKUP" "`$angie_oidf_config_sha256" "Angie OIDF configuration backup" || return 1
    if [ -L "`$OIDF_CA_TARGET" ] || { [ -e "`$OIDF_CA_TARGET" ] && [ ! -f "`$OIDF_CA_TARGET" ]; }; then
      echo "OIDF mTLS CA target must be a regular file or absent: `$OIDF_CA_TARGET" >&2
      return 1
    elif [ -f "`$OIDF_CA_TARGET" ]; then
      previous_ca_kind="file"
      if ! previous_ca_sha256="`$(sha256_file "`$OIDF_CA_TARGET")"; then
        echo "Existing OIDF CA bundle could not be hashed" >&2
        return 1
      fi
      cp --preserve=mode,ownership,timestamps -- "`$OIDF_CA_TARGET" "`$OIDF_CA_BACKUP"
      require_sha256 "`$OIDF_CA_BACKUP" "`$previous_ca_sha256" "OIDF CA rollback backup"
    else
      previous_ca_kind="missing"
    fi
  fi
  previous_current_target=""
  if [ -L "`$DEPLOYMENTS/current.json" ]; then
    previous_current_target="`$(readlink "`$DEPLOYMENTS/current.json")"
  fi
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
    podman run --rm --name "`$CONTAINER_NAME-migrate-`$(date +%s)" \
      --network "`$NETWORK_NAME" \
      -v "`$CONFIG_PATH:/app/.env.yaml:ro" \
      -v "`$KEYS_PATH:/var/lib/nazo_oauth/keys:rw" \
      -v "`$AVATARS_PATH:/var/lib/nazo_oauth/avatars:rw" \
      "`$IMAGE" nazo-oauth-migrate
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
  assert_pending_lease
  install_oidf_ca
  assert_pending_lease

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
    Invoke-Checked scp $localRemoteScript "${RemoteHost}:$remoteScript"
    $remoteStarted = $true
    Invoke-Checked ssh $RemoteHost @($deployCommand)

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

    Invoke-Checked ssh $RemoteHost @($commitCommand)
    $remoteStarted = $false
    Write-Host "Deployment verified: $image deployment-success"
}
catch {
    if ($remoteStarted) {
        & ssh $RemoteHost $rollbackCommand
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Automatic rollback command failed; inspect $RemoteHost immediately"
        }
    }
    throw
}
finally {
    Remove-Item -LiteralPath $localRemoteScript, $uiArchive, $archive -Force -ErrorAction SilentlyContinue
}
