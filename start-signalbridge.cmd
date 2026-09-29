@echo off
cd /d "%~dp0"
.venv\Scripts\python.exe scripts\sb.py up
if errorlevel 1 pause

