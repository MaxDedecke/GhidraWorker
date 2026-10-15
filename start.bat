@echo off
rem GhidraWorker starten (Windows). Legt beim ersten Start eine virtuelle Python-Umgebung an.
setlocal
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
    echo Erstelle Python-Umgebung...
    py -3 -m venv .venv 2>nul || python -m venv .venv
    if errorlevel 1 (
        echo Python 3.10+ wird benoetigt: https://www.python.org/downloads/
        pause
        exit /b 1
    )
    .venv\Scripts\python.exe -m pip install --upgrade pip >nul
    .venv\Scripts\python.exe -m pip install -r requirements.txt || (pause & exit /b 1)
)
.venv\Scripts\python.exe -m ghidraworker serve %*
pause
