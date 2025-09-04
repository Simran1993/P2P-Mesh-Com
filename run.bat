@echo off
echo Running Mesh Network Application...
if exist dist\MeshNetwork.exe (
    cd dist
    MeshNetwork.exe
) else (
    echo Executable not found! Please build first using build.bat
    pause
)
