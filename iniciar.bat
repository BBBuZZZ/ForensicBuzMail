@echo off
chcp 65001 >nul
title ForensicBuzMail - Analizador Forense de Correos

echo =====================================================================
echo           FORENSICBUZMAIL - ANALIZADOR FORENSE DE CORREOS
echo      Entorno 100%% Local, Privado y Seguro (Offline Forensics)
echo =====================================================================
echo.

:: 1. Intenta py launcher (Python oficial de Windows)
py -c "import sys" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [OK] Motor Python detectado via 'py' launcher.
    echo [INFO] Iniciando servidor ForensicBuzMail en puerto 8080...
    echo.
    py server.py
    if %ERRORLEVEL% NEQ 0 (
        goto fallback_node
    )
    pause
    exit /b 0
)

:: 2. Intenta comando python directamente
python -c "import sys" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [OK] Motor Python detectado via 'python'.
    echo [INFO] Iniciando servidor ForensicBuzMail en puerto 8080...
    echo.
    python server.py
    if %ERRORLEVEL% NEQ 0 (
        goto fallback_node
    )
    pause
    exit /b 0
)

:fallback_node
:: 3. Intenta Node.js en PATH
where node >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [OK] Motor Node.js detectado en PATH.
    echo [INFO] Iniciando servidor ForensicBuzMail en puerto 8080...
    echo.
    node server.js
    pause
    exit /b 0
)

:: 4. Intenta ruta fija de Node.js
if exist "C:\Program Files\nodejs\node.exe" (
    echo [OK] Motor Node.js detectado en C:\Program Files\nodejs.
    echo [INFO] Iniciando servidor ForensicBuzMail en puerto 8080...
    echo.
    "C:\Program Files\nodejs\node.exe" server.js
    pause
    exit /b 0
)

echo.
echo [ERROR] No se pudo encontrar un motor de ejecucion (Python o Node.js).
echo Por favor asegurese de tener instalado Python 3 o Node.js.
echo.
pause
exit /b 1
