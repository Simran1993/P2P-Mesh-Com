@echo off
echo Building Mesh Network Application...
echo.

REM Activate virtual environment if it exists
if exist venv\Scripts\activate.bat (
    echo Activating virtual environment...
    call venv\Scripts\activate.bat
)

REM Install build requirements
echo Installing build requirements...
pip install -r requirements-build.txt

REM Clean and build
echo Cleaning previous builds...
python build.py

echo.
echo Build complete! Check the dist/ folder for your executable.
pause
