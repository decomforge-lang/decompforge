# Verificacion de los scripts de Ghidra (adaptadores de la Fase 2).
#
# Hace dos cosas:
#   1. Compila `ExportDecompForge.java` e `ImportDecompForge.java` con `javac`
#      contra los JAR de una instalacion real de Ghidra. Esto detecta cualquier
#      cambio de API que el editor no ve.
#   2. Si hay un compilador C, ejecuta el ciclo completo en modo headless:
#      importar un binario de prueba -> exportar `re-1.0` -> validar -> aplicar
#      `updates` -> reexportar -> comprobar que los cambios persisten.
#
# El binario de prueba se compila en `target/ghidra-test` y NUNCA se versiona.
#
# Uso:
#   ./scripts/check-ghidra.ps1
#   ./scripts/check-ghidra.ps1 -GhidraHome D:\ghidra_12.2_PUBLIC -JavaHome C:\jdk-25
#   ./scripts/check-ghidra.ps1 -CompileOnly
#
# Variables de entorno equivalentes: GHIDRA_HOME, JAVA_HOME.
param(
    [string]$GhidraHome = $env:GHIDRA_HOME,
    [string]$JavaHome = $env:JAVA_HOME,
    [switch]$CompileOnly
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

# En Windows PowerShell la salida de stderr de un programa nativo se convierte
# en error terminante cuando ErrorActionPreference es Stop. Este ayudante
# ejecuta el programa, captura todo y devuelve el codigo de salida real.
function Invoke-Native([string]$Exe, [string[]]$Arguments) {
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = & $Exe @Arguments 2>&1
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    return [pscustomobject]@{ Output = @($output); Code = $code }
}

function Resolve-GhidraRoot([string]$Path) {
    if (-not $Path -or -not (Test-Path $Path)) { return $null }
    if (Test-Path (Join-Path $Path "support\analyzeHeadless.bat")) {
        return (Resolve-Path $Path).Path
    }
    # El ZIP oficial extrae una carpeta interna:
    # ghidra_<version>_PUBLIC\ghidra_<version>_PUBLIC
    $inner = Get-ChildItem $Path -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path (Join-Path $_.FullName "support\analyzeHeadless.bat") } |
        Select-Object -First 1
    if ($inner) { return $inner.FullName }
    return $null
}

function Find-Ghidra([string]$Hint) {
    $resolved = Resolve-GhidraRoot $Hint
    if ($resolved) { return $resolved }
    $roots = @("$env:USERPROFILE\Documents", "$env:USERPROFILE\Downloads", "C:\", "C:\tools", "C:\opt")
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        $candidates = Get-ChildItem $root -Directory -Filter "ghidra_*" -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending
        foreach ($candidate in $candidates) {
            $resolved = Resolve-GhidraRoot $candidate.FullName
            if ($resolved) { return $resolved }
        }
    }
    return $null
}

function Get-JavaMajor([string]$JavaExe) {
    $result = Invoke-Native $JavaExe @("-version")
    $text = ($result.Output | Out-String)
    if ($text -match 'version "(\d+)') { return [int]$Matches[1] }
    return 0
}

function Find-Jdk([string]$Hint, [int]$Minimum) {
    $candidates = @()
    if ($Hint) { $candidates += $Hint }
    $onPath = Get-Command java -ErrorAction SilentlyContinue
    if ($onPath) { $candidates += (Split-Path (Split-Path $onPath.Source -Parent) -Parent) }
    foreach ($root in @(
            "$env:ProgramFiles\Eclipse Adoptium",
            "$env:ProgramFiles\Java",
            "$env:USERPROFILE\Documents\tools",
            "$env:USERPROFILE\Downloads")) {
        if (-not (Test-Path $root)) { continue }
        $candidates += (Get-ChildItem $root -Directory -Filter "jdk*" -ErrorAction SilentlyContinue |
            ForEach-Object { $_.FullName })
    }
    $best = $null
    $bestMajor = 0
    foreach ($candidate in $candidates) {
        $javaExe = Join-Path $candidate "bin\java.exe"
        if (-not (Test-Path $javaExe)) { continue }
        $major = Get-JavaMajor $javaExe
        if ($major -ge $Minimum -and $major -gt $bestMajor) {
            $best = $candidate
            $bestMajor = $major
        }
    }
    if ($best) { return [pscustomobject]@{ Home = $best; Major = $bestMajor } }
    return $null
}

$ghidra = Find-Ghidra $GhidraHome
if (-not $ghidra) {
    throw "no se encontro Ghidra; pasa -GhidraHome o define GHIDRA_HOME"
}

# Ghidra declara la version minima de Java en application.properties.
$required = 0
$properties = Join-Path $ghidra "Ghidra\application.properties"
if (Test-Path $properties) {
    $line = Select-String -Path $properties -Pattern '^application\.java\.min=' | Select-Object -First 1
    if ($line) { $required = [int]($line.Line -replace '^application\.java\.min=', '') }
}

$jdk = Find-Jdk $JavaHome $required
if (-not $jdk) {
    throw "no se encontro un JDK $required o superior; pasa -JavaHome o define JAVA_HOME"
}
Write-Host "==> Ghidra: $ghidra" -ForegroundColor Cyan
Write-Host "==> JDK:    $($jdk.Home) (Java $($jdk.Major))" -ForegroundColor Cyan
$javac = Join-Path $jdk.Home "bin\javac.exe"
if (-not (Test-Path $javac)) {
    throw "no se encontro javac en $($jdk.Home); se necesita un JDK, no un JRE"
}

$out = Join-Path $PWD "target\ghidra-scripts"
Remove-Item -Recurse -Force $out -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $out | Out-Null

$jars = (Get-ChildItem $ghidra -Recurse -Filter *.jar -ErrorAction SilentlyContinue |
    ForEach-Object { $_.FullName }) -join ';'
$scripts = @(
    "adapters\ghidra\scripts\ExportDecompForge.java",
    "adapters\ghidra\scripts\ImportDecompForge.java"
)
Write-Host "==> javac ($($scripts.Count) scripts)" -ForegroundColor Cyan
$compile = Invoke-Native $javac (@("-encoding", "UTF-8", "-nowarn", "-cp", $jars, "-d", $out) + $scripts)
$compile.Output | ForEach-Object { Write-Host $_ }
if ($compile.Code -ne 0) {
    throw "fallo: javac no pudo compilar los scripts (codigo $($compile.Code))"
}
Write-Host "compilacion OK: $out" -ForegroundColor Green

if ($CompileOnly) { return }

# --- Ciclo completo en headless ------------------------------------------------
$gcc = (Get-Command gcc -ErrorAction SilentlyContinue).Source
if (-not $gcc) {
    Write-Warning "sin gcc: se omite el ciclo headless (solo compilacion)"
    return
}

$work = Join-Path $PWD "target\ghidra-test"
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $work | Out-Null
$source = Join-Path $work "sample.c"
$binary = Join-Path $work "sample.exe"
@"
int df_add(int a, int b) { return a + b; }
int df_twice(int x) { return df_add(x, x); }
int main(void) { return df_twice(21) == 42 ? 0 : 1; }
"@ | Set-Content -Encoding ASCII $source
$build = Invoke-Native $gcc @("-O0", "-g0", "-o", $binary, $source)
$build.Output | ForEach-Object { Write-Host $_ }
if ($build.Code -ne 0) { throw "fallo: gcc no pudo compilar el binario de prueba" }

$env:JAVA_HOME = $jdk.Home
$headless = Join-Path $ghidra "support\analyzeHeadless.bat"
$project = Join-Path $work "proj"
New-Item -ItemType Directory -Force -Path $project | Out-Null
$scriptPath = Join-Path $PWD "adapters\ghidra\scripts"

function Invoke-Headless([string[]]$Arguments, [string]$Step) {
    Write-Host "==> headless: $Step" -ForegroundColor Cyan
    $result = Invoke-Native $headless $Arguments
    $result.Output |
        Select-String -Pattern "ERROR|DecompForge:" |
        ForEach-Object { Write-Host $_ }
    if ($result.Code -ne 0) { throw "fallo: $Step (codigo $($result.Code))" }
}

$export1 = Join-Path $work "export.json"
Invoke-Headless @(
    $project, "df_test", "-import", $binary, "-scriptPath", $scriptPath,
    "-postScript", "ExportDecompForge.java", $export1
) "importar + exportar"
if (-not (Test-Path $export1)) { throw "no se genero $export1" }

# Validacion con el cliente Python si esta disponible.
$pythonCommand = @()
if ($env:DECOMPFORGE_PYTHON) {
    $pythonCommand = @($env:DECOMPFORGE_PYTHON)
} else {
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd) {
        $pythonCommand = @($cmd.Source)
    } else {
        $py = Get-Command py -ErrorAction SilentlyContinue
        if ($py) { $pythonCommand = @($py.Source, "-3") }
    }
}
if ($pythonCommand.Count -gt 0) {
    $bootstrap = "import sys; sys.path.insert(0, 'adapters/python'); " +
        "from decompforge_re.cli import main; raise SystemExit(main(sys.argv[1:]))"
    Write-Host "==> validar export con el cliente Python" -ForegroundColor Cyan
    $pythonExe = $pythonCommand[0]
    $pythonPrefix = @()
    if ($pythonCommand.Count -gt 1) {
        $pythonPrefix = $pythonCommand[1..($pythonCommand.Count - 1)]
    }
    $validation = Invoke-Native $pythonExe ($pythonPrefix + @("-c", $bootstrap, "validate", $export1))
    $validation.Output | ForEach-Object { Write-Host $_ }
    if ($validation.Code -ne 0) { throw "el export no valida contra re-1.0" }
} else {
    Write-Warning "sin Python: se omite la validacion del esquema"
}

# Parche: renombrar la primera funcion con instrucciones y anadir comentarios.
$doc = Get-Content $export1 -Raw | ConvertFrom-Json
$target = $doc.functions | Where-Object { $_.instructions -and $_.instructions.Count -gt 1 } |
    Select-Object -First 1
if (-not $target) { throw "el export no contiene funciones con instrucciones" }
$entry = $target.address
$instructionAddress = $target.instructions[1].address
$commentEntry = "comentario de entrada (DecompForge)"
$commentInstruction = "comentario de instruccion (DecompForge)"
$probe = [ordered]@{
    schema_version = "re-1.0"
    kind           = "updates"
    functions      = @(
        [ordered]@{
            address   = $entry
            name      = "df_probe"
            signature = "int df_probe(int a, int b)"
            comments  = @(
                [ordered]@{ address = $entry; text = $commentEntry },
                [ordered]@{ address = $instructionAddress; text = $commentInstruction }
            )
        }
    )
}
$updates = Join-Path $work "updates.json"
$probe | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 $updates
Invoke-Headless @(
    $project, "df_test", "-process", "sample.exe", "-noanalysis",
    "-scriptPath", $scriptPath,
    "-postScript", "ImportDecompForge.java", $updates
) "aplicar updates"

$export2 = Join-Path $work "export2.json"
Invoke-Headless @(
    $project, "df_test", "-process", "sample.exe", "-noanalysis",
    "-scriptPath", $scriptPath,
    "-postScript", "ExportDecompForge.java", $export2, "-deleteProject"
) "reexportar"
if (-not (Test-Path $export2)) { throw "no se genero $export2" }

$after = Get-Content $export2 -Raw | ConvertFrom-Json
$applied = $after.functions | Where-Object { $_.address -eq $entry } | Select-Object -First 1
if (-not $applied) { throw "la funcion $entry desaparecio tras la importacion" }
if ($applied.name -ne "df_probe") { throw "el nombre no persiste: $($applied.name)" }
if ($applied.signature -ne "int df_probe(int a, int b)") {
    throw "la firma no persiste: $($applied.signature)"
}
$texts = @($applied.comments | ForEach-Object { $_.text })
if ($texts -notcontains $commentEntry) { throw "falta el comentario de entrada" }
if ($texts -notcontains $commentInstruction) { throw "falta el comentario de instruccion" }

Write-Host "Ghidra OK: compilacion + ciclo export/validate/apply/export" -ForegroundColor Green
