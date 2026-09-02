param(
    [string]$FrontendSource = (Join-Path $PSScriptRoot "..\..\Pape-Reg"),
    [switch]$SkipBackend
)

$ErrorActionPreference = "Stop"

$sdkRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$frontendRoot = (Resolve-Path -LiteralPath $FrontendSource).Path
$frontendOutput = Join-Path $sdkRoot "static\usercenter"

if (-not (Test-Path -LiteralPath (Join-Path $frontendRoot "package.json") -PathType Leaf)) {
    throw "Frontend source is not a Node project: $frontendRoot"
}

Push-Location $frontendRoot
try {
    if (-not (Test-Path -LiteralPath (Join-Path $frontendRoot "node_modules") -PathType Container)) {
        & npm.cmd ci
        if ($LASTEXITCODE -ne 0) {
            throw "npm ci failed with exit code $LASTEXITCODE"
        }
    }

    & npm.cmd run build -- "--base=/usercenter/" "--outDir=$frontendOutput" "--emptyOutDir"
    if ($LASTEXITCODE -ne 0) {
        throw "Frontend build failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}

if (-not $SkipBackend) {
    Push-Location $sdkRoot
    try {
        & go build -o pape-sdk.exe ./cmd/pape-sdk
        if ($LASTEXITCODE -ne 0) {
            throw "Backend build failed with exit code $LASTEXITCODE"
        }
    }
    finally {
        Pop-Location
    }
}

Write-Host "SDK frontend built from $frontendRoot"
