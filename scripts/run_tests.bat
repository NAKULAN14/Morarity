@echo off
setlocal
cd /d "%~dp0.."
set PYTHONPATH=backend
backend\venv\Scripts\pytest.exe backend\tests
endlocal
