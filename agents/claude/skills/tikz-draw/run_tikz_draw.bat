@echo off
setlocal
set "CLAUDE_HOME=%USERPROFILE%\.claude"
set "SKILL_DIR=%CLAUDE_HOME%\skills\tikz-draw"
set "OPENCLAW_WORKSPACE=%CLAUDE_HOME%"
set "OPENCLAW_SECRETS_FILE=%CLAUDE_HOME%\secrets.json"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
if exist "%CLAUDE_HOME%\.venv\Scripts\python.exe" (
    set "PATH=%CLAUDE_HOME%\.venv\Scripts;%PATH%"
    set "PYTHON_EXE=%CLAUDE_HOME%\.venv\Scripts\python.exe"
) else (
    set "PYTHON_EXE=python"
)
set "PYTHONPATH=%SKILL_DIR%;%PYTHONPATH%"
pushd "%SKILL_DIR%" >nul
"%PYTHON_EXE%" "%SKILL_DIR%\tikz_draw.py" %*
set "_exit=%ERRORLEVEL%"
popd >nul
exit /b %_exit%
