param(
    [Parameter(Mandatory = $true)]
    [string]$RemoteHost,
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
    [string]$RemoteUiPath = "/opt/nazo-oauth/ui",
    [string]$LocalUiDist = "../NazoAuthWeb/dist",
    [string]$PublishPort = "",
    [string]$HealthUrl = "https://auth.nazo.run/health",
    [string]$DiscoveryUrl = "https://auth.nazo.run/.well-known/openid-configuration",
    [string]$ExpectedIssuer = "https://auth.nazo.run",
    [switch]$SkipBuild,
    [switch]$SkipMigrate
)

$ErrorActionPreference = "Stop"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed: $FilePath $($Arguments -join ' ')"
    }
}

function Get-CommandOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )

    $output = & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed: $FilePath $($Arguments -join ' ')"
    }
    return ($output | Select-Object -First 1)
}

function ConvertTo-ShellLiteral {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    $singleQuote = [string][char]39
    $escapedQuote = $singleQuote + "\" + $singleQuote + $singleQuote
    return $singleQuote + $Value.Replace($singleQuote, $escapedQuote) + $singleQuote
}

if (-not $ImageTag) {
    $ImageTag = "main-$(Get-CommandOutput git rev-parse --short=7 HEAD)"
}

$image = "${ImageRepository}:$ImageTag"
$safeTag = $ImageTag -replace '[^A-Za-z0-9_.-]', '-'
$archive = Join-Path ([System.IO.Path]::GetTempPath()) "nazo-oauth-server-$safeTag.tar"
$uiArchive = Join-Path ([System.IO.Path]::GetTempPath()) "nazo-oauth-web-$safeTag.tar.gz"
$localRemoteScript = Join-Path ([System.IO.Path]::GetTempPath()) "nazo-oauth-deploy-$safeTag.sh"

Write-Host "Deploying $image to $RemoteHost"

if (-not (Test-Path -LiteralPath (Join-Path $LocalUiDist "index.html"))) {
    throw "Missing frontend dist index.html: $LocalUiDist"
}

if (-not $SkipBuild) {
    Invoke-Checked docker @("build", "-f", "Containerfile", "-t", $image, ".")
}

if (Test-Path -LiteralPath $archive) {
    Remove-Item -LiteralPath $archive -Force
}
if (Test-Path -LiteralPath $uiArchive) {
    Remove-Item -LiteralPath $uiArchive -Force
}
Invoke-Checked docker @("save", $image, "-o", $archive)
Invoke-Checked tar @("-C", $LocalUiDist, "-czf", $uiArchive, ".")
$remoteTempDir = Get-CommandOutput ssh $RemoteHost @("mktemp", "-d", "/tmp/nazo-oauth-deploy.XXXXXX")
$remoteArchive = "$remoteTempDir/nazo-oauth-server-$safeTag.tar"
$remoteUiArchive = "$remoteTempDir/nazo-oauth-web-$safeTag.tar.gz"
$remoteScript = "$remoteTempDir/deploy.sh"
Invoke-Checked scp $archive "${RemoteHost}:$remoteArchive"
Invoke-Checked scp $uiArchive "${RemoteHost}:$remoteUiArchive"

$skipMigrateValue = if ($SkipMigrate) { "1" } else { "0" }
$remoteBody = @"
set -euo pipefail

IMAGE=$(ConvertTo-ShellLiteral $image)
REMOTE_ARCHIVE=$(ConvertTo-ShellLiteral $remoteArchive)
REMOTE_UI_ARCHIVE=$(ConvertTo-ShellLiteral $remoteUiArchive)
REMOTE_SCRIPT=$(ConvertTo-ShellLiteral $remoteScript)
CONTAINER_NAME=$(ConvertTo-ShellLiteral $ContainerName)
NETWORK_NAME=$(ConvertTo-ShellLiteral $Network)
NETWORK_SUBNET=$(ConvertTo-ShellLiteral $NetworkSubnet)
NETWORK_GATEWAY=$(ConvertTo-ShellLiteral $NetworkGateway)
CONTAINER_IP=$(ConvertTo-ShellLiteral $IPAddress)
CONFIG_PATH=$(ConvertTo-ShellLiteral $RemoteConfigPath)
KEYS_PATH=$(ConvertTo-ShellLiteral $RemoteKeysPath)
AVATARS_PATH=$(ConvertTo-ShellLiteral $RemoteAvatarsPath)
UI_PATH=$(ConvertTo-ShellLiteral $RemoteUiPath)
PUBLISH_PORT=$(ConvertTo-ShellLiteral $PublishPort)
SKIP_MIGRATE=$(ConvertTo-ShellLiteral $skipMigrateValue)

cleanup() {
  rm -f "`$REMOTE_ARCHIVE" "`$REMOTE_UI_ARCHIVE" "`$REMOTE_SCRIPT"
  rmdir "`$(dirname "`$REMOTE_SCRIPT")" 2>/dev/null || true
}
trap cleanup EXIT

test -f "`$CONFIG_PATH"
test -d "`$KEYS_PATH"
test -d "`$AVATARS_PATH"
mkdir -p "`$UI_PATH"
find "`$UI_PATH" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
tar -xzf "`$REMOTE_UI_ARCHIVE" -C "`$UI_PATH"

podman load -i "`$REMOTE_ARCHIVE"
podman image exists "`$IMAGE"

if podman network exists "`$NETWORK_NAME"; then
  network_inspect="`$(podman network inspect "`$NETWORK_NAME")"
  if [ -n "`$NETWORK_SUBNET" ] && ! printf '%s\n' "`$network_inspect" | grep -F "`$NETWORK_SUBNET" >/dev/null; then
    echo "Existing Podman network `$NETWORK_NAME does not contain required subnet `$NETWORK_SUBNET" >&2
    exit 1
  fi
else
  create_network_args=()
  if [ -n "`$NETWORK_SUBNET" ]; then
    create_network_args+=(--subnet "`$NETWORK_SUBNET")
  fi
  if [ -n "`$NETWORK_GATEWAY" ]; then
    create_network_args+=(--gateway "`$NETWORK_GATEWAY")
  fi
  podman network create "`${create_network_args[@]}" "`$NETWORK_NAME"
fi

if [ "`$SKIP_MIGRATE" != "1" ]; then
  migrate_name="`$CONTAINER_NAME-migrate-`$(date +%s)"
  podman run --rm --name "`$migrate_name" \
    --network "`$NETWORK_NAME" \
    -v "`$CONFIG_PATH:/app/.env.yaml:ro" \
    -v "`$KEYS_PATH:/var/lib/nazo_oauth/keys:rw" \
    -v "`$AVATARS_PATH:/var/lib/nazo_oauth/avatars:rw" \
    "`$IMAGE" nazo-oauth-migrate
fi

if podman container exists "`$CONTAINER_NAME"; then
  podman rm -f "`$CONTAINER_NAME"
fi

publish_args=()
if [ -n "`$PUBLISH_PORT" ]; then
  publish_args=(-p "`$PUBLISH_PORT")
fi

podman run -d --name "`$CONTAINER_NAME" \
  --network "`$NETWORK_NAME" --ip "`$CONTAINER_IP" \
  "`${publish_args[@]}" \
  -v "`$CONFIG_PATH:/app/.env.yaml:ro" \
  -v "`$KEYS_PATH:/var/lib/nazo_oauth/keys:rw" \
  -v "`$AVATARS_PATH:/var/lib/nazo_oauth/avatars:rw" \
  "`$IMAGE" nazo-oauth-server

podman inspect "`$CONTAINER_NAME" --format 'container={{.Name}} image={{.ImageName}} status={{.State.Status}}'
podman inspect "`$CONTAINER_NAME" --format '{{range `$name, `$conf := .NetworkSettings.Networks}}network={{`$name}} ip={{`$conf.IPAddress}}{{println}}{{end}}'
actual_ip="`$(podman inspect "`$CONTAINER_NAME" --format '{{range `$name, `$conf := .NetworkSettings.Networks}}{{println `$conf.IPAddress}}{{end}}' | awk 'NF { print; exit }')"
if [ "`$actual_ip" != "`$CONTAINER_IP" ]; then
  echo "Container `$CONTAINER_NAME started with IP `$actual_ip, expected `$CONTAINER_IP" >&2
  exit 1
fi

curl -fsS --max-time 10 "http://`$CONTAINER_IP:8000/health" >/dev/null
discovery="`$(curl -fsS --max-time 10 "http://`$CONTAINER_IP:8000/.well-known/openid-configuration")"
printf '%s\n' "`$discovery" | grep -F '"issuer"' >/dev/null
"@

Set-Content -LiteralPath $localRemoteScript -Value $remoteBody -Encoding UTF8
try {
    Invoke-Checked scp $localRemoteScript "${RemoteHost}:$remoteScript"
    Invoke-Checked ssh $RemoteHost @("bash", $remoteScript)
}
finally {
    Remove-Item -LiteralPath $localRemoteScript -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $uiArchive -Force -ErrorAction SilentlyContinue
}

$health = Invoke-WebRequest -Uri $HealthUrl -UseBasicParsing -TimeoutSec 20
if ($health.StatusCode -ne 200) {
    throw "Health probe failed: HTTP $($health.StatusCode)"
}

$discovery = Invoke-WebRequest -Uri $DiscoveryUrl -UseBasicParsing -TimeoutSec 20
if ($discovery.StatusCode -ne 200) {
    throw "Discovery probe failed: HTTP $($discovery.StatusCode)"
}

$metadata = $discovery.Content | ConvertFrom-Json
if ($metadata.issuer -ne $ExpectedIssuer) {
    throw "Unexpected issuer in discovery document: $($metadata.issuer)"
}

Write-Host "Deployment verified: $image"
