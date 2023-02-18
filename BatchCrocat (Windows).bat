@echo off
cd /D %~dp0
set /p Folder= "Folder Name: "
python3 crocat.py --dir %Folder%
pause