@echo off
setlocal

set "MSVC_DIR=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.44.35207"
set "SDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0"
set "SDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0"
set "SDK_BIN=C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64"

set "PATH=%MSVC_DIR%\bin\Hostx64\x64;%SDK_BIN%;%PATH%"
set "INCLUDE=%MSVC_DIR%\include;%SDK_INC%\ucrt;%SDK_INC%\um;%SDK_INC%\shared"
set "LIB=%MSVC_DIR%\lib\x64;%SDK_LIB%\ucrt\x64;%SDK_LIB%\um\x64"
set "TMP=D:\Games\Sound Voltex Nabla\sdvx_accuracy"
set "TEMP=D:\Games\Sound Voltex Nabla\sdvx_accuracy"

cd /d "D:\Games\Sound Voltex Nabla\sdvx_accuracy"

del /f /q "D:\Games\Sound Voltex Nabla\sdvx_accuracy.dll.old" >nul 2>&1
if exist "D:\Games\Sound Voltex Nabla\sdvx_accuracy.dll" (
    move /y "D:\Games\Sound Voltex Nabla\sdvx_accuracy.dll" "D:\Games\Sound Voltex Nabla\sdvx_accuracy.dll.old" >nul 2>&1
)

if exist "imgui.obj" (
    cl.exe /nologo /std:c++20 /EHsc /O2 /MD /utf-8 /DNOMINMAX /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS /I"." /I"imgui" ^
        sdvx_accuracy.cpp ^
        imgui.obj imgui_draw.obj imgui_tables.obj imgui_widgets.obj imgui_impl_dx9.obj ^
        /LD /Fe:"D:\Games\Sound Voltex Nabla\sdvx_accuracy.dll" ^
        /link user32.lib gdi32.lib d3d9.lib imm32.lib
) else (
    cl.exe /nologo /std:c++20 /EHsc /O2 /MD /utf-8 /DNOMINMAX /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS /I"." /I"imgui" ^
        sdvx_accuracy.cpp ^
        imgui\imgui.cpp ^
        imgui\imgui_draw.cpp ^
        imgui\imgui_tables.cpp ^
        imgui\imgui_widgets.cpp ^
        imgui\imgui_impl_dx9.cpp ^
        /LD /Fe:"D:\Games\Sound Voltex Nabla\sdvx_accuracy.dll" ^
        /link user32.lib gdi32.lib d3d9.lib imm32.lib
)

if errorlevel 1 (
    echo [ERROR] Build failed!
    exit /b 1
)

del /f /q "D:\Games\Sound Voltex Nabla\sdvx_accuracy.lib" "D:\Games\Sound Voltex Nabla\sdvx_accuracy.exp" "D:\Games\Sound Voltex Nabla\sdvx_accuracy.dll.old" >nul 2>&1
echo [SUCCESS] Built D:\Games\Sound Voltex Nabla\sdvx_accuracy.dll
