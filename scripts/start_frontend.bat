@echo off
echo ========================================================
echo   Starting Moriarty Verification Workstation (Vite)
echo ========================================================
cd /d "%~dp0\..\frontend"
npm run dev -- --host 127.0.0.1 --port 5173
