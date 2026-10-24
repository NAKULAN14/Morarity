@echo off
echo ========================================================
echo   Starting Moriarty Verification Backend (FastAPI)
echo ========================================================
cd /d "%~dp0\.."
set PYTHONPATH=backend;%PYTHONPATH%
backend\venv\Scripts\uvicorn.exe --app-dir backend app.main:app --host 127.0.0.1 --port 8000 --reload
