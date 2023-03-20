wpeinit
net use M: "\\providyncorpdc\Software\Windows OSs\arbor" /USER:providyninc\william.higgs
diskpart /S X:\files\partition.txt
mkdir W:\files
xcopy X:\files\* W:\files
"X:\files\compname.exe"
"X:\WinNTSetup3\WinNTSetup_x64.exe" nt6 /source:"M:\install.wim" /syspart:S: /tempdrive:W: /drivers:"M:\t460drive" /disableuac /unattend:"W:\files\autounattend.xml" /wimindex:1 /setup /reboot /runafter:{xcopy "X:\files\start.bat" "W:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"} /bcd:{UEFI}