@echo off
rem SPDX-License-Identifier: MIT
rem
rem Double-click this to install the modified build over the installed client.
rem
rem Why this exists: wireguard.exe is the application, not an installer. Double
rem clicking it launches the client; it does not register services or copy
rem anything anywhere. Installing means replacing the executable that is already
rem there, and the services have to be stopped first or the old code keeps
rem running from memory (Windows lets you overwrite a running executable, which
rem makes a plain copy look like it worked). This wraps deploy-zhuanban.ps1,
rem which does exactly that, so it can be started with a double click instead of
rem from a shell.

setlocal

chcp 65001 >nul 2>&1
set "HERE=%~dp0"
set "SCRIPT=%HERE%deploy-zhuanban.ps1"

rem Stopping services and writing to Program Files both need an elevated token.
net session >nul 2>&1
if errorlevel 1 (
	echo 需要管理员权限，正在请求提权……
	powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
	exit /b
)

if not exist "%SCRIPT%" (
	echo 找不到 deploy-zhuanban.ps1。
	echo 请把它和本文件放在同一个目录里（解压后应该在一起）。
	echo.
	pause
	exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"
set "RESULT=%ERRORLEVEL%"

echo.
if "%RESULT%"=="0" (
	echo 完成。
) else (
	echo 脚本以错误码 %RESULT% 结束，请把上面的信息发出来。
)
pause
exit /b %RESULT%
