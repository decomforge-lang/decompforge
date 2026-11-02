# Cobertura local del nucleo (RNF-06) en Windows.
#
# `cargo llvm-cov` necesita el runtime `profiler_builtins`, que rustup solo
# distribuye para el host MSVC. Si tu toolchain por defecto es GNU, este script
# localiza Visual Studio con `vswhere`, carga su entorno (cl.exe, link.exe) y
# ejecuta la cobertura con el toolchain MSVC.
#
# Uso:
#   ./scripts/coverage.ps1                # resumen; falla si el nucleo baja del 80 % de lineas
#   ./scripts/coverage.ps1 -Html          # ademas genera target/llvm-cov/html/index.html
#   ./scripts/coverage.ps1 -- --text      # argumentos extra para `cargo llvm-cov`
#
# Equivalentes en Linux/macOS: `make coverage`.
param(
    [switch]$Html,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ExtraArgs
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

$toolchain = "stable-x86_64-pc-windows-msvc"
if (-not (rustup toolchain list | Select-String -SimpleMatch $toolchain)) {
    throw "falta el toolchain MSVC: rustup toolchain install $toolchain"
}
if (-not (rustup component list --toolchain $toolchain | Select-String "llvm-tools.*(installed)")) {
    rustup component add llvm-tools --toolchain $toolchain
}

$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    throw "no se encontro vswhere.exe; instala Visual Studio Build Tools con el componente 'Desarrollo para el escritorio con C++'"
}
$vs = & $vswhere -latest -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath
if (-not $vs) {
    throw "no hay Visual Studio con herramientas C++; instala el componente 'Desarrollo para el escritorio con C++'"
}
$vcvars = Join-Path $vs "VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $vcvars)) {
    throw "no se encontro vcvars64.bat en $vs"
}

$cargoArgs = @("+$toolchain", "llvm-cov", "--package", "decompforge-core", "--all-targets")
if ($Html) {
    $cargoArgs += @("--html")
} else {
    $cargoArgs += @("--fail-under-lines", "80")
}
if ($ExtraArgs) { $cargoArgs += $ExtraArgs }

Write-Host "==> cargo $($cargoArgs -join ' ')  (entorno: $vs)" -ForegroundColor Cyan
# cmd es necesario para que `call vcvars64.bat` exporte el entorno a cargo.
cmd /c "call `"$vcvars`" >nul 2>&1 && cargo $($cargoArgs -join ' ') 2>&1" |
    ForEach-Object { Write-Host $_ }
$code = $LASTEXITCODE
if ($code -ne 0) {
    throw "fallo: cargo $($cargoArgs -join ' ') (codigo $code)"
}
if ($Html) {
    Write-Host "informe: target/llvm-cov/html/index.html" -ForegroundColor Green
}
