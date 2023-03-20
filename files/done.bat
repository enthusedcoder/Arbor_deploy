mkdir W:\files
xcopy X:\files\* W:\files
xcopy X:\files\start.bat "W:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
net use M: /delete