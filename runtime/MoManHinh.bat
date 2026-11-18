@echo off
chcp 65001 >nul
title Mo man hinh phone (scrcpy - tat audio)
cd /d "%~dp0"
set "ADB=%~dp0adb.exe"
set "SCRCPY_SERVER_PATH=%~dp0scrcpy-server"

echo ============================================
echo    MO MAN HINH PHONE  (scrcpy, KHONG audio)
echo ============================================
echo.
echo May dang cam:
"%ADB%" devices
echo.

if not "%~1"=="" goto :one

rem Khong truyen serial: neu chi 1 may thi scrcpy tu chon; nhieu may se bao loi -> chay lai kem serial
"%~dp0scrcpy.exe" --no-audio --stay-awake
goto :end

:one
echo Mo may: %~1
"%~dp0scrcpy.exe" -s %~1 --no-audio --stay-awake

:end
echo.
echo Neu bao "multiple devices": chay lai kem serial, vi du:  MoManHinh.bat R9CNJA4G9WK
echo (copy serial o cot dau tien phia tren)
pause
