param(
    [Parameter(Mandatory=$true)]
    [string]$Team,

    [int]$Port = 5000
)

$TeamDir = Join-Path $PSScriptRoot "instances\$Team"
$ArtifactPath = Join-Path $TeamDir "artifact"
$SecretPath = Join-Path $TeamDir "secret.bin"
$MetadataPath = Join-Path $TeamDir "metadata.json"

if (-not (Test-Path $TeamDir)) {
    Write-Host "[-] Team instance not found: $Team"
    exit 1
}

if (-not (Test-Path $ArtifactPath)) {
    Write-Host "[-] Artifact directory not found."
    exit 1
}

if (-not (Test-Path $SecretPath)) {
    Write-Host "[-] Secret not found."
    exit 1
}

if (-not (Test-Path $MetadataPath)) {
    Write-Host "[-] Metadata not found."
    exit 1
}

$Metadata = Get-Content $MetadataPath -Raw | ConvertFrom-Json

$PublicSeed = $Metadata.public_seed

if (-not $PublicSeed) {
    Write-Host "[-] public_seed missing from metadata."
    exit 1
}

$Registers = $Metadata.vm_registers

if (-not $Registers) {
    Write-Host "[-] vm_registers missing from metadata."
    exit 1
}

$VmStateBytes = @()

foreach ($value in $Registers) {
    $VmStateBytes += [byte]$value
    $VmStateBytes += [byte]$value
    $VmStateBytes += [byte]$value
    $VmStateBytes += [byte]$value
}

$VmState = (
    $VmStateBytes |
    ForEach-Object {
        "{0:x2}" -f $_
    }
) -join ""

Write-Host ""
Write-Host "============================================================"
Write-Host "Ghost Protocol"
Write-Host "============================================================"
Write-Host "Team:        $Team"
Write-Host "Port:        $Port"
Write-Host "Public seed: $PublicSeed"
Write-Host "VM state:    $VmState"
Write-Host "============================================================"
Write-Host ""

docker run --rm `
    --name "ghost-$Team" `
    -p "${Port}:5000" `
    -v "${ArtifactPath}:/app/artifact:ro" `
    -v "${SecretPath}:/app/instance/secret.bin:ro" `
    -e "INSTANCE_SECRET=/app/instance/secret.bin" `
    -e "PUBLIC_SEED=$PublicSeed" `
    -e "VM_STATE=$VmState" `
    ghost-protocol
