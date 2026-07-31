[CmdletBinding()]
param(
    [ValidateSet('install', 'status', 'doctor', 'plan', 'update', 'rollback', 'recover')]
    [string]$Action = 'update',
    [string]$SshHost = 'hostinger',
    [string]$Config = '/etc/nazoauth/update.json',
    [string]$Version = '',
    [ValidateSet('auto', 'podman', 'docker', 'host')]
    [string]$Runtime = 'auto',
    [string]$PublicUrl = 'https://auth.nazo.run',
    [string]$DataRoot = '/var/lib/nazoauth'
)

$ErrorActionPreference = 'Stop'

if ($SshHost -notmatch '^[A-Za-z0-9._-]+$') {
    throw 'SshHost must be a configured SSH host alias'
}
if ($Config -notmatch '^/[A-Za-z0-9._/-]+$') {
    throw 'Config must be a safe absolute remote path'
}
if ($Version -and $Version -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$') {
    throw 'Version must be an immutable semantic tag'
}

function ConvertTo-ShellWord {
    param([string]$Value)

    return "'" + $Value.Replace("'", "'\"'\"'") + "'"
}

function Invoke-NazoAuthCtl {
    param([string[]]$Arguments)

    $remote = @('sudo', 'nazoauthctl', '--config', $Config) + $Arguments
    $remoteCommand = ($remote | ForEach-Object { ConvertTo-ShellWord $_ }) -join ' '
    & ssh -o BatchMode=yes -o ConnectTimeout=15 -- $SshHost $remoteCommand
    if ($LASTEXITCODE -ne 0) {
        throw "remote nazoauthctl failed with exit code $LASTEXITCODE"
    }
}

$versionArgs = if ($Version) { @('--to', $Version) } else { @() }
switch ($Action) {
    'install' {
        Invoke-NazoAuthCtl (@(
            'install', '--runtime', $Runtime, '--public-url', $PublicUrl,
            '--data-root', $DataRoot
        ) + $versionArgs)
    }
    'status' { Invoke-NazoAuthCtl @('status') }
    'doctor' { Invoke-NazoAuthCtl @('doctor') }
    'plan' { Invoke-NazoAuthCtl (@('update', '--plan') + $versionArgs) }
    'update' { Invoke-NazoAuthCtl (@('update', '--yes') + $versionArgs) }
    'rollback' { Invoke-NazoAuthCtl @('rollback', '--yes') }
    'recover' { Invoke-NazoAuthCtl @('recover', '--yes') }
}
