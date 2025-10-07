Set-StrictMode -Version Latest
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Push-Location $scriptDir

# Crée un environnement virtuel isolé
$venv = Join-Path $scriptDir "venv_gui"
if (-not (Test-Path $venv)) { python -m venv $venv }
$python = Join-Path $venv "Scripts\python.exe"
$pip = Join-Path $venv "Scripts\pip.exe"

# Installe PyInstaller
& $pip install --upgrade pip
& $pip install pyinstaller

# Compile en un seul exécutable
# ⚠️ accesschk.exe doit se trouver manuellement dans le même dossier que le script ou l'exe final
$spec = @(
  "--onefile",
  "--noconfirm",
  "--noconsole",
  "--name","AccessChkGUI",
  "accesschk_gui_tk.py"
)
& $python -m PyInstaller @spec

Write-Host "`nBuild terminé. L'exécutable se trouve dans dist\AccessChkGUI.exe"
Pop-Location
