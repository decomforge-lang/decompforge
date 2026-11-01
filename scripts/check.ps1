# Equivalente a `make check` para Windows (PowerShell).
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

# En Windows PowerShell, la salida de stderr de un programa nativo se convierte
# en "error" y con ErrorActionPreference=Stop corta el script (cargo escribe
# "Finished"/"Compiling" en stderr). Redirigimos y comprobamos el codigo real.
function Invoke-Cargo([string[]]$CargoArgs) {
    Write-Host "==> cargo $($CargoArgs -join ' ')" -ForegroundColor Cyan
    $previous = $ErrorActionPreference
    try {
        # Con Stop, cualquier linea de stderr de cargo se convierte en error
        # terminante antes de poder comprobar su codigo de salida real.
        $ErrorActionPreference = "Continue"
        & cargo @CargoArgs 2>&1 | ForEach-Object { Write-Host $_ }
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    if ($code -ne 0) {
        throw "fallo: cargo $($CargoArgs -join ' ') (codigo $code)"
    }
}

Invoke-Cargo @("fmt", "--all", "--", "--check")
Invoke-Cargo @("clippy", "--workspace", "--all-targets", "--", "-D", "warnings")
Invoke-Cargo @("test", "--workspace")

# La documentacion tambien es parte de la calidad: un enlace roto debe fallar.
$previous = $env:RUSTDOCFLAGS
try {
    $env:RUSTDOCFLAGS = "-D warnings"
    Invoke-Cargo @("doc", "--workspace", "--no-deps")
} finally {
    $env:RUSTDOCFLAGS = $previous
}

# Adaptadores de la Fase 2. Son opcionales: si no hay Python o falta
# `jsonschema`, se avisa y se continua (la CI siempre los ejecuta).
$python = $env:DECOMPFORGE_PYTHON
if (-not $python) {
    $candidate = Get-Command python -ErrorAction SilentlyContinue
    if ($candidate) { $python = $candidate.Source }
}
if ($python -and (Test-Path $python)) {
    function Invoke-Python([string[]]$PythonArgs) {
        Write-Host "==> python $($PythonArgs -join ' ')" -ForegroundColor Cyan
        $previous = $ErrorActionPreference
        try {
            $ErrorActionPreference = "Continue"
            & $python @PythonArgs 2>&1 | ForEach-Object { Write-Host $_ }
            $code = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $previous
        }
        if ($code -ne 0) {
            throw "fallo: python $($PythonArgs -join ' ') (codigo $code)"
        }
    }

    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        & $python -c "import jsonschema" 2>$null
        $has_schema = $LASTEXITCODE -eq 0
    } finally {
        $ErrorActionPreference = $previous
    }
    if ($has_schema) {
        Invoke-Python @("-m", "unittest", "discover", "-s", "adapters/python/tests", "-t", "adapters/python")

        Write-Host "==> export re-json + validacion" -ForegroundColor Cyan
        # El proyecto de comprobacion se regenera en cada ejecucion para que el
        # script sea idempotente.
        if (Test-Path "target/check-re") {
            Remove-Item -Recurse -Force "target/check-re"
        }
        Invoke-Cargo @("run", "-q", "-p", "decompforge-cli", "--", "init", "check", "--sample", "--dir", "target/check-re")
        Invoke-Cargo @("run", "-q", "-p", "decompforge-cli", "--", "export", "--format", "re-json", "--project", "target/check-re/check.dfproj", "--output", "target/check-re/export.json")

        $previous = $env:PYTHONPATH
        try {
            $env:PYTHONPATH = "adapters/python"
            # `-c` en vez de `-m`: el Python embebido de Windows ignora
            # PYTHONPATH en `-m` por su fichero `._pth`.
            $bootstrap = "import sys; sys.path.insert(0, 'adapters/python'); from decompforge_re.cli import main; raise SystemExit(main(sys.argv[1:]))"
            Invoke-Python @("-c", $bootstrap, "validate", "target/check-re/export.json")
        } finally {
            $env:PYTHONPATH = $previous
        }
    } else {
        Write-Warning "adaptadores omitidos: falta el modulo de Python 'jsonschema'"
    }
} else {
    Write-Warning "adaptadores omitidos: no se encontro Python"
}

Write-Host "Todo OK" -ForegroundColor Green
