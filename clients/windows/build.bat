@echo off
rem Build securefile_send.exe with MSVC (static CRT, no runtime dependency).
rem Requires Visual Studio Build Tools with the "Desktop development with C++" workload.
setlocal enabledelayedexpansion
cd /d "%~dp0"

rem --- find vcvars64.bat -----------------------------------------------------
set "VCVARS="
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "!VSWHERE!" (
  rem Delayed expansion keeps the (x86) parenthesis in the path from breaking the for-loop.
  for /f "usebackq delims=" %%i in (`"!VSWHERE!" -latest -products * -property installationPath`) do (
    if exist "%%i\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%%i\VC\Auxiliary\Build\vcvars64.bat"
  )
)
if not defined VCVARS (
  for %%e in (BuildTools Community Professional Enterprise) do (
    for %%y in (2022 2019) do (
      set "P=%ProgramFiles(x86)%\Microsoft Visual Studio\%%y\%%e\VC\Auxiliary\Build\vcvars64.bat"
      if exist "!P!" if not defined VCVARS set "VCVARS=!P!"
    )
  )
)
if not defined VCVARS (
  echo [error] vcvars64.bat not found. Install VS Build Tools + "Desktop development with C++".
  exit /b 1
)

echo Using: !VCVARS!
call "!VCVARS!" >nul
if errorlevel 1 ( echo [error] vcvars failed & exit /b 1 )

echo Compiling resources...
rc /nologo /fo assets.res assets.rc
if errorlevel 1 ( echo [error] rc failed & exit /b 1 )

echo Compiling...
cl /nologo /W3 /O2 /MT /utf-8 /GS /DUNICODE /D_UNICODE /D_CRT_SECURE_NO_WARNINGS ^
   main.c util.c uploader.c httpserver.c registry.c tray.c assets.res ^
   /Fe:securefile_send.exe ^
   /link /SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup ^
   ws2_32.lib winhttp.lib advapi32.lib shell32.lib bcrypt.lib user32.lib comdlg32.lib
if errorlevel 1 ( echo [error] build failed & exit /b 1 )

del /q *.obj assets.res >nul 2>&1
echo.
echo Built securefile_send.exe
endlocal
