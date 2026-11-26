#Requires -Version 5.1
<#
Builds Local AI Code Agent into a Windows executable and a Setup.exe installer.

Steps:
  1. Create/refresh a build-only virtual environment (Python 3.11).
  2. Install PyInstaller.
  3. Run the unit tests (packaging aborts if they fail).
  4. Build dist\LocalAICodeAgent\LocalAICodeAgent.exe (onedir, windowed).
  5. Ensure Inno Setup 6 is available (auto-install via winget if missing).
  6. Build installer\output\LocalAICodeAgent-Setup.exe.
#>
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$AppName = 'LocalAICodeAgent'

# --- Python build environment ---------------------------------------------
$Python = Get-Command py -ErrorAction SilentlyContinue
if (-not $Python) { throw 'Python Launcher (py.exe) not found. Install Python 3.11 or 3.12 x64 first.' }

if (-not (Test-Path '.build-venv')) { py -3.11 -m venv .build-venv }
$Py = Join-Path $Root '.build-venv\Scripts\python.exe'
if (-not (Test-Path $Py)) { throw 'Could not create build virtual environment with Python 3.11.' }

& $Py -m pip install --upgrade pip pyinstaller
if ($LASTEXITCODE -ne 0) { throw 'Failed to install build dependencies.' }

# --- Tests -----------------------------------------------------------------
& $Py -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) { throw 'Unit tests failed; refusing to package.' }

# --- Build the executable --------------------------------------------------
if (Test-Path 'build') { Remove-Item 'build' -Recurse -Force }
if (Test-Path 'dist') { Remove-Item 'dist' -Recurse -Force }

& $Py -m PyInstaller --noconfirm --clean --windowed --name $AppName `
    --icon src\assets\forge.ico `
    --add-data "src\assets;assets" `
    --paths src `
    --collect-submodules tools `
    --hidden-import config --hidden-import providers --hidden-import agent_support `
    src\app.py
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller build failed.' }
Write-Host "App EXE built at dist\$AppName\$AppName.exe" -ForegroundColor Green

# --- Locate or install Inno Setup -----------------------------------------
function Find-ISCC {
    @(
        (Get-Command ISCC.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue),
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
    ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
}

$Iscc = Find-ISCC
if (-not $Iscc) {
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        Write-Host 'Inno Setup 6 not found. Installing it via winget...' -ForegroundColor Yellow
        try {
            winget install --id JRSoftware.InnoSetup -e --silent `
                --accept-package-agreements --accept-source-agreements | Out-Host
        } catch {
            Write-Warning "winget install of Inno Setup did not complete cleanly: $_"
        }
        $Iscc = Find-ISCC
    }
}

if (-not $Iscc) {
    Write-Warning 'Inno Setup 6 is not installed and could not be installed automatically.'
    Write-Warning 'Install it from https://jrsoftware.org/isinfo.php then run:'
    Write-Warning "  & `"$env:ProgramFiles (x86)\Inno Setup 6\ISCC.exe`" installer\LocalAICodeAgent.iss"
    Write-Host "The application executable is ready at dist\$AppName\$AppName.exe" -ForegroundColor Green
    exit 0
}

# --- Build the installer ---------------------------------------------------
New-Item -ItemType Directory -Force -Path 'installer\output' | Out-Null
& $Iscc 'installer\LocalAICodeAgent.iss'
if ($LASTEXITCODE -ne 0) { throw 'Inno Setup installer build failed.' }
Write-Host 'Build complete: installer\output\LocalAICodeAgent-Setup.exe' -ForegroundColor Green
