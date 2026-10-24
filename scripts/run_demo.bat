@echo off
setlocal
cd /d "%~dp0.."
set PYTHONPATH=backend
backend\venv\Scripts\python.exe demo.py
endlocal
