# Lanzador Universal PowerShell para ForensicBuzMail
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "          FORENSICBUZMAIL - ANALIZADOR FORENSE DE CORREOS            " -ForegroundColor Cyan
Write-Host "      Entorno 100% Local, Privado y Seguro (Offline Forensics)      " -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""

# Check py launcher
$hasPy = (Get-Command py -ErrorAction SilentlyContinue)
if ($hasPy) {
    Write-Host "[OK] Motor detectado: Python (via py launcher)" -ForegroundColor Green
    Write-Host "[INFO] Iniciando servidor ForensicBuzMail en puerto 8080..." -ForegroundColor Yellow
    py server.py
    exit 0
}

# Check python
$hasPython = (Get-Command python -ErrorAction SilentlyContinue)
if ($hasPython) {
    Write-Host "[OK] Motor detectado: Python" -ForegroundColor Green
    Write-Host "[INFO] Iniciando servidor ForensicBuzMail en puerto 8080..." -ForegroundColor Yellow
    python server.py
    exit 0
}

# Check Node.js
$hasNode = (Get-Command node -ErrorAction SilentlyContinue)
if ($hasNode) {
    Write-Host "[OK] Motor detectado: Node.js" -ForegroundColor Green
    Write-Host "[INFO] Iniciando servidor ForensicBuzMail en puerto 8080..." -ForegroundColor Yellow
    node server.js
    exit 0
}

if (Test-Path "C:\Program Files\nodejs\node.exe") {
    Write-Host "[OK] Motor detectado: C:\Program Files\nodejs\node.exe" -ForegroundColor Green
    Write-Host "[INFO] Iniciando servidor ForensicBuzMail en puerto 8080..." -ForegroundColor Yellow
    & "C:\Program Files\nodejs\node.exe" server.js
    exit 0
}

Write-Host "[ERROR] No se encontró Python ni Node.js en el sistema." -ForegroundColor Red
pause
exit 1
