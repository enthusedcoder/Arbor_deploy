Function Show-DesktopIcons{
$ErrorActionPreference = "SilentlyContinue"
If ($Error) {$Error.Clear()}
$RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
If (Test-Path $RegistryPath) {
	$Res = Get-ItemProperty -Path $RegistryPath -Name "HideIcons"
	If (-Not($Res)) {
		New-ItemProperty -Path $RegistryPath -Name "HideIcons" -Value "0" -PropertyType DWORD -Force | Out-Null
	}
	$Check = (Get-ItemProperty -Path $RegistryPath -Name "HideIcons").HideIcons
	If ($Check -NE 0) {
		New-ItemProperty -Path $RegistryPath -Name "HideIcons" -Value "0" -PropertyType DWORD -Force | Out-Null
	}
}
$RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons"
If (-Not(Test-Path $RegistryPath)) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "HideDesktopIcons" -Force | Out-Null
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons" -Name "NewStartPanel" -Force | Out-Null
}
$RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
If (-Not(Test-Path $RegistryPath)) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons" -Name "NewStartPanel" -Force | Out-Null
}
If (Test-Path $RegistryPath) {
	## -- My Computer
	$Res = Get-ItemProperty -Path $RegistryPath -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
	If (-Not($Res)) {
		New-ItemProperty -Path $RegistryPath -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value "0" -PropertyType DWORD -Force | Out-Null
	}
	$Check = (Get-ItemProperty -Path $RegistryPath -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}")."{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
	If ($Check -NE 0) {
		New-ItemProperty -Path $RegistryPath -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value "0" -PropertyType DWORD -Force | Out-Null
	}
	## -- Control Panel
	$Res = Get-ItemProperty -Path $RegistryPath -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}"
	If (-Not($Res)) {
		New-ItemProperty -Path $RegistryPath -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -Value "0" -PropertyType DWORD -Force | Out-Null
	}
	$Check = (Get-ItemProperty -Path $RegistryPath -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}")."{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}"
	If ($Check -NE 0) {
		New-ItemProperty -Path $RegistryPath -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -Value "0" -PropertyType DWORD -Force | Out-Null
	}
	## -- User's Files
	$Res = Get-ItemProperty -Path $RegistryPath -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}"
	If (-Not($Res)) {
		New-ItemProperty -Path $RegistryPath -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Value "0" -PropertyType DWORD -Force | Out-Null
	}
	$Check = (Get-ItemProperty -Path $RegistryPath -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}")."{59031a47-3f72-44a7-89c5-5595fe6b30ee}"
	If ($Check -NE 0) {
		New-ItemProperty -Path $RegistryPath -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Value "0" -PropertyType DWORD -Force | Out-Null
	}
	## -- Recycle Bin
	$Res = Get-ItemProperty -Path $RegistryPath -Name "{645FF040-5081-101B-9F08-00AA002F954E}"
	If (-Not($Res)) {
		New-ItemProperty -Path $RegistryPath -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Value "0" -PropertyType DWORD -Force | Out-Null
	}
	$Check = (Get-ItemProperty -Path $RegistryPath -Name "{645FF040-5081-101B-9F08-00AA002F954E}")."{645FF040-5081-101B-9F08-00AA002F954E}"
	If ($Check -NE 0) {
		New-ItemProperty -Path $RegistryPath -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Value "0" -PropertyType DWORD -Force | Out-Null
	}
	## -- Network
	$Res = Get-ItemProperty -Path $RegistryPath -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}"
	If (-Not($Res)) {
		New-ItemProperty -Path $RegistryPath -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -Value "0" -PropertyType DWORD -Force | Out-Null
	}
	$Check = (Get-ItemProperty -Path $RegistryPath -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}")."{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}"
	If ($Check -NE 0) {
		New-ItemProperty -Path $RegistryPath -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -Value "0" -PropertyType DWORD -Force | Out-Null
	}
}
If ($Error) {$Error.Clear()}
}
Function Set-AutoLogon{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [String[]]$DefaultUsername,
        [Parameter(Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [String[]]$DefaultPassword,
        [Parameter(Mandatory=$False,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [AllowEmptyString()]
        [String[]]$AutoLogonCount,
        [Parameter(Mandatory=$False,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [AllowEmptyString()]
        [String[]]$Script
    )
    Begin
    {
        $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        $RegROPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    }
    Process
    {
        try
        {
            Set-ItemProperty $RegPath "AutoAdminLogon" -Value "1" -type String
            Set-ItemProperty $RegPath "DefaultUsername" -Value "$DefaultUsername" -type String
            Set-ItemProperty $RegPath "DefaultPassword" -Value "$DefaultPassword" -type String
            if($AutoLogonCount)
            {
                Set-ItemProperty $RegPath "AutoLogonCount" -Value "$AutoLogonCount" -type DWord
            }
            else
            {
                Set-ItemProperty $RegPath "AutoLogonCount" -Value "1" -type DWord
            }
            if($Script)
            {
                Set-ItemProperty $RegROPath "(Default)" -Value "$Script" -type String
            }
            else
            {
                Set-ItemProperty $RegROPath "(Default)" -Value "" -type String
            }
        }
        catch
        {

            Write-Output "An error had occured $Error"
        }
    }
    
    End
    {
        #End
    }

}
function Use-RunAs
{
    param([Switch]$Check)
    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()`
        ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if ($Check) { return $IsAdmin }
    if ($MyInvocation.ScriptName -ne "")
    {
        if (-not $IsAdmin)
        {
            try
            {
                $arg = "-file `"$($MyInvocation.ScriptName)`""
                Start-Process "$psHome\powershell.exe" -Verb Runas -ArgumentList $arg -ErrorAction 'stop'
            }
            catch
            {
                Write-Warning "Error - Failed to restart script with runas"
                break
            }
            exit # Quit this session of powershell
        }
    }
    else
    {
        Write-Warning "Error - Script must be saved as a .ps1 file first"
        break
    }
}
Add-Type -AssemblyName System.IO.Compression.FileSystem
function Unzip
{
    param([string]$zipfile, [string]$outpath)

    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
}
function Show-MsgBox
{

 [CmdletBinding()]
    param(
    [Parameter(Position=0, Mandatory=$true)] [string]$Prompt,
    [Parameter(Position=1, Mandatory=$false)] [string]$Title ="",
    [Parameter(Position=2, Mandatory=$false)] [ValidateSet("Information", "Question", "Critical", "Exclamation")] [string]$Icon ="Information",
    [Parameter(Position=3, Mandatory=$false)] [ValidateSet("OKOnly", "OKCancel", "AbortRetryIgnore", "YesNoCancel", "YesNo", "RetryCancel")] [string]$BoxType ="OkOnly",
    [Parameter(Position=4, Mandatory=$false)] [ValidateSet(1,2,3)] [int]$DefaultButton = 1
    )
[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.VisualBasic") | Out-Null
switch ($Icon) {
            "Question" {$vb_icon = [microsoft.visualbasic.msgboxstyle]::Question }
            "Critical" {$vb_icon = [microsoft.visualbasic.msgboxstyle]::Critical}
            "Exclamation" {$vb_icon = [microsoft.visualbasic.msgboxstyle]::Exclamation}
            "Information" {$vb_icon = [microsoft.visualbasic.msgboxstyle]::Information}}
switch ($BoxType) {
            "OKOnly" {$vb_box = [microsoft.visualbasic.msgboxstyle]::OKOnly}
            "OKCancel" {$vb_box = [microsoft.visualbasic.msgboxstyle]::OkCancel}
            "AbortRetryIgnore" {$vb_box = [microsoft.visualbasic.msgboxstyle]::AbortRetryIgnore}
            "YesNoCancel" {$vb_box = [microsoft.visualbasic.msgboxstyle]::YesNoCancel}
            "YesNo" {$vb_box = [microsoft.visualbasic.msgboxstyle]::YesNo}
            "RetryCancel" {$vb_box = [microsoft.visualbasic.msgboxstyle]::RetryCancel}}
switch ($Defaultbutton) {
            1 {$vb_defaultbutton = [microsoft.visualbasic.msgboxstyle]::DefaultButton1}
            2 {$vb_defaultbutton = [microsoft.visualbasic.msgboxstyle]::DefaultButton2}
            3 {$vb_defaultbutton = [microsoft.visualbasic.msgboxstyle]::DefaultButton3}}
$popuptype = $vb_icon -bor $vb_box -bor $vb_defaultbutton
$ans = [Microsoft.VisualBasic.Interaction]::MsgBox($prompt,$popuptype,$title)
return $ans
} #end function
If (!(Test-Path C:\files\ninite.exe))
{
[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    Use-RunAs
   DISM /Online /Enable-Feature /FeatureName:NetFx3 /All
   If (!(Test-Path "${env:ProgramFiles(x86)}\Dell\CommandUpdate"))
    {
        Start-Process "C:\files\Systems-Management_Application_FXD2R_WN32_2.3.0_A00-00.EXE" -ArgumentList '/s' -Wait -Verbose
    }
        Start-Process "${env:ProgramFiles(x86)}\Dell\CommandUpdate\dcu-cli.exe" -Wait
   Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory "Private"
   Invoke-WebRequest 'https://ninite.com/.net4.6.2-7zip-air-cutepdf-java8-shockwave-silverlight/ninite.exe' -OutFile C:\files\ninite.exe -Verbose
   Start-Process C:\files\ninite-silent.exe -Wait -Verbose
      Get-PackageProvider -Name NuGet -ForceBootstrap
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    Try
    {
        Install-module Carbon -Force -ErrorAction Stop
    }
    Catch
    {
        Install-module Carbon -Force -AllowClobber
    }
mkdir "$env:APPDATA\autoscript"
Set-RegistryKeyValue -Path 'hklm:\Software\Microsoft\Windows\CurrentVersion\Run' -Name "deploy" -String '%APPDATA%\autoscript\go.bat' -Expand
iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))
& "C:\ProgramData\chocolatey\redirects\RefreshEnv.cmd"
Invoke-Webrequest https://gist.githubusercontent.com/whiggs/306d5b36349b463b720cb78796907777/raw/57e25c29cabbbffb839b3a911e5b00e708e0f3c9/winup.ps1 -outfile $env:APPDATA\autoscript\boxstarter.ps1 -Verbose
echo "cd /d %~dp0" 'PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command ".\boxstarter.ps1"' | Out-file -filepath "$env:APPDATA\autoscript\go.bat" -Encoding ascii
Try
    {
        Install-module PSWindowsUpdate -Force -ErrorAction Stop
    }
Catch
    {
        Install-module PSWindowsUpdate -Force -AllowClobber
}
Try
    {
        Install-module CustomizeWindows10 -Force -ErrorAction Stop
    }
Catch
    {
        Install-module CustomizeWindows10 -Force -AllowClobber
}
mkdir "C:\files\autoit"
Invoke-WebRequest "https://www.autoitscript.com/files/autoit3/autoit-v3.zip" -OutFile "C:\files\autoit.zip"
Unzip "C:\files\autoit.zip" "C:\files\autoit"
$vpn = Add-VpnConnection -Name "Arbor VPN" -ServerAddress remote.arborpharma.com -AllUserConnection $true -AuthenticationMethod MSChapv2 -TunnelType Sstp -EncryptionLevel Maximum -PassThru -Verbose
#Add-VpnConnection -Name "Arbor VPN" -ServerAddress remote.arborpharma.com -AllUserConnection -AuthenticationMethod MSChapv2 -EncryptionLevel Maximum -TunnelType Sstp -Verbose
Show-DesktopIcons
Enable-ExplorerThisPC
Enable-Windows7VolumeMixer
Enable-ShowFileExtension
Enable-ShowHiddenFiles
choco install adobereader -y
Start-Process "C:\files\win_activate.exe" -Wait -Verbose
Start-Process -filepath "${env:ProgramFiles(x86)}\Dell\CommandUpdate\dcu-cli.exe" -Wait
Add-WUServiceManager -ServiceID "7971f918-a847-4430-9279-4a52d1efe18d" -confirm:$false -Verbose
Remove-Item -Path 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\start.bat' -Force -Verbose
Restart-Computer -Force
}
Else
{
    Remove-Item -Path 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\start.bat' -Force
}
<#
Start-Process 'iexplore.exe' -ArgumentList 'https://ninite.com/java8-7zip-cutepdf-shockwave-air-.net4.6.2-silverlight' -Wait
    Stop-Service wuauserv
$cred = Get-Credential -UserName "$env:USERDOMAIN\$env:USERNAME" -Message 'Please input your Providyn credentials to connect to network share'
$user = $cred.UserName
$pass = $cred.password
ConvertFrom-SecureString $pass | out-File "$env:USERPROFILE\documents\file.txt"
$new = Get-Content "$env:USERPROFILE\Documents\file.txt" | ConvertTo-SecureString
Write-Host $user
Write-Host $(Convert-SecureStringToString $new)
Install-script Get-Github -Confirm:$false
Get-Github.ps1 -User whiggs -Repository 'office_auto_install'
Move-Item -Path "$env:USERPROFILE\AppData\Local\Temp\office_auto_install-master.zip" -Destination "$env:USERPROFILE\Desktop\office_auto_install-master.zip"
Unzip "$env:USERPROFILE\Desktop\office_auto_install-master.zip" "$env:USERPROFILE\Desktop"
. "$env:USERPROFILE\Desktop\office_auto_install-master\Install-OfficeClickToRun.ps1"
Install-OfficeClickToRun "$env:USERPROFILE\Desktop\office_auto_install-master\configuration.xml"
Get-WUInstall -autoreboot -acceptall -MicrosoftUpdate
Start-Sleep 10
Remove-RegistryKeyValue -Path 'hklm:\Software\Microsoft\Windows\CurrentVersion\Run' -Name "deploy"

Enable UAC:
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA  -Value 1
#>