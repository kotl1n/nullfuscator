@echo off
setlocal
set "DIR=%~dp0"
set "ROOT=%DIR%.."

set "JAR="
if exist "%DIR%nullfuscator-obf.jar" set "JAR=%DIR%nullfuscator-obf.jar"
if not defined JAR if exist "%ROOT%\build\nullfuscator-obf.jar" set "JAR=%ROOT%\build\nullfuscator-obf.jar"
if not defined JAR if exist "%ROOT%\nullfuscator-obf.jar" set "JAR=%ROOT%\nullfuscator-obf.jar"

if not defined JAR (
  echo error: could not find nullfuscator-obf.jar. Run 'python3 scripts/build.py' first. 1>&2
  exit /b 1
)

java -jar "%JAR%" %*
