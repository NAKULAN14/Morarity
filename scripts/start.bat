@echo off
echo ========================================================
echo   Starting Moriarty Workstation (Backend + Frontend)
echo ========================================================
start "Moriarty Backend API (:8000)" cmd /k "%~dp0start_backend.bat"
timeout /t 2 >nul
start "Moriarty Workstation (:5173)" cmd /k "%~dp0start_frontend.bat"
