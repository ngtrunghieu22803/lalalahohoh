@echo off
cd /d G:\LogaToolChangerV2
echo Starting local server on 8790...
start "local_server" cmd /c "cd local_server && dotnet run -c Release --no-build -- 8790"
timeout /t 4 >nul
echo Starting LogaChanger (local)...
start "" "LogaChanger.local.exe"
