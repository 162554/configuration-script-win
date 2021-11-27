function Do-Next {
    Write-Host "What you can do next?`n`n" -ForegroundColor Yellow
    Write-Host " * Change your display scale" -ForegroundColor White
    Write-Host " * Turn off rubbish focus assistance" -ForegroundColor White
    Write-Host " * Teams turn on dark theme and start in background." -ForegroundColor White
    Write-Host " * Manually check store updates again." -ForegroundColor White
    Write-Host " * Manually sign in store personal account." -ForegroundColor White
    Write-Host " * Set Google as default search engine." -ForegroundColor White
    Write-Host " * Sign in To do." -ForegroundColor White
    Write-Host " * Sign in Sticky Notes." -ForegroundColor White
    Write-Host " * Sign in Mail UWP." -ForegroundColor White
    Write-Host " * Sign in browser extensions to use password manager." -ForegroundColor White
    Write-Host " * Turn on bitlocker" -ForegroundColor White
    Write-Host " * Sign in VSCode to turn on settings sync." -ForegroundColor White
    Write-Host " * Sign in Spotify and edit start up settings" -ForegroundColor White
    Write-Host " * Sign in WeChat" -ForegroundColor White
    Write-Host " * Sign in Visual Studio" -ForegroundColor White
    Write-Host " * Set Windows Terminal as default" -ForegroundColor White
    Write-Host " * Sign in the Xbox app" -ForegroundColor White
    Write-Host " * Activate Windows" -ForegroundColor White
}

function Get-IsElevated {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    if ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
    { Write-Output $true }      
    else
    { Write-Output $false }   
}

function Install-StoreApp {
    param (
        [string]$storeAppId,
        [string]$wingetAppName
    )

    if ("$(winget list --name $wingetAppName --exact --source msstore --accept-source-agreements)".Contains("--")) { 
        Write-Host "$wingetAppName is already installed!" -ForegroundColor Green
    }
    else {
        Write-Host "Attempting to download $wingetAppName..." -ForegroundColor Green
        winget install --id $storeAppId.ToUpper() --name $wingetAppName  --exact --source msstore --accept-package-agreements --accept-source-agreements
    }
}

function Install-IfNotInstalled {
    param (
        [string]$package
    )

    if ("$(winget list -e --id $package --source winget)".Contains("--")) { 
        Write-Host "$package is already installed!" -ForegroundColor Green
    }
    else {
        Write-Host "Attempting to install: $package..." -ForegroundColor Green
        winget install -e --id $package --source winget
    }
}

function Install-OtherSoftWare {
    param (
        [string]$softwareurl
    )
    $softwarename = $softwareurl.split("/")[-1]
    Write-Host "Download .exe for   $($softwarename )" -ForegroundColor Green
    $outpath = "$env:USERPROFILE\Downloads\$softwarename"
    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($softwareurl, $outpath)
    Start-Sleep -Seconds 10
    Write-Host "Install-OtherSoftWare : $softwarename..." -ForegroundColor Green
    Start-Process -Filepath  $outpath  "/S"  -Wait 2>&1 | out-null
}

function Set-WallPaper($Image) {
    Add-Type -TypeDefinition @" 
    using System; 
    using System.Runtime.InteropServices;

    public class Params
    { 
        [DllImport("User32.dll",CharSet=CharSet.Unicode)] 
        public static extern int SystemParametersInfo (Int32 uAction, 
                                                       Int32 uParam, 
                                                       String lpvParam, 
                                                       Int32 fuWinIni);
    }
"@ 
    $SPI_SETDESKWALLPAPER = 0x0014
    $UpdateIniFile = 0x01
    $SendChangeEvent = 0x02
    $fWinIni = $UpdateIniFile -bor $SendChangeEvent
    $ret = [Params]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $Image, $fWinIni)
}

Write-Host "-----------------------------" -ForegroundColor Green
Write-Host "        PART 1  - Prepare    " -ForegroundColor Green
Write-Host "-----------------------------" -ForegroundColor Green

if (-not(Get-IsElevated)) { 
    throw "Please run this script as an administrator" 
}
Write-Host "Please make sure you have logged in to Microsoft Accounts and OneDrive."
Write-Host "Press the [y] key to continue to steps which requires reboot."
$pressedKey = Read-Host
Write-Host "You pressed: $($pressedKey)"
if ($pressedKey -eq 'y') {
    Write-Host "Please provide me your email." -ForegroundColor Yellow
    $email = Read-Host
    Write-Host "Please provide me your name." -ForegroundColor Yellow
    $name = Read-Host
    $driveLetter = (Get-Location).Drive.Name
    $computerName = Read-Host "Enter New Computer Name if you want to rename it: ($($env:COMPUTERNAME))"
    if (-not ([string]::IsNullOrEmpty($computerName))) {
        Write-Host "Renaming computer to $computerName..." -ForegroundColor Green
        cmd /c "bcdedit /set {current} description `"$computerName`""
        Rename-Computer -NewName $computerName
    }
    $screen = (Get-WmiObject -Class Win32_VideoController)
    $screenX = $screen.CurrentHorizontalResolution
    $screenY = $screen.CurrentVerticalResolution
    Write-Host "Got screen: $screenX x $screenY" -ForegroundColor Green

    Write-Host "-----------------------------" -ForegroundColor Green
    Write-Host "        PART 2  - Install    " -ForegroundColor Green
    Write-Host "-----------------------------" -ForegroundColor Green

    Do-Next

    Write-Host "Triggering Store to upgrade all apps..." -ForegroundColor Green
    $namespaceName = "root\cimv2\mdm\dmmap"
    $className = "MDM_EnterpriseModernAppManagement_AppManagement01"
    $wmiObj = Get-WmiObject -Namespace $namespaceName -Class $className
    $wmiObj.UpdateScanMethod() | Format-Table -AutoSize


    ## Reimage 
    # Install Winget
    if (-not $(Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host "Installing WinGet..." -ForegroundColor Green
        Start-Process "ms-appinstaller:?source=https://aka.ms/getwinget"
        while (-not $(Get-Command winget -ErrorAction SilentlyContinue)) {
            Write-Host "Winget is still not found!" -ForegroundColor Yellow
            Start-Sleep -Seconds 5
        }
    }
    if ("$(winget list --id Microsoft.VisualStudioCode --source winget)".Contains("--")) { 
        Write-Host "Microsoft.VisualStudioCode is already installed!" -ForegroundColor Green
    }
    else {
        Write-Host "Attempting to download Microsoft VS Code..." -ForegroundColor Green
        winget install --exact --id Microsoft.VisualStudioCode --scope Machine --interactive --source winget
    }

    Install-IfNotInstalled "Microsoft.WindowsTerminal"
    #Install-IfNotInstalled "Microsoft.Teams"
    #Install-IfNotInstalled "Microsoft.Office"
    Install-IfNotInstalled "Microsoft.OneDrive"
    #Install-IfNotInstalled "Microsoft.PowerShell"
    #Install-IfNotInstalled "Microsoft.dotnet"
    ## Java
    #Install-IfNotInstalled "JetBrains.IntelliJIDEA.Ultimate"   #bug 无法判断是否已安装
    Install-IfNotInstalled "EclipseAdoptium.Temurin.11"
    ## Netease
    Install-IfNotInstalled "Netease.CloudMusic"
    Install-IfNotInstalled "Microsoft.Edge"
    Install-IfNotInstalled "Microsoft.EdgeWebView2Runtime"
    #Install-IfNotInstalled "Microsoft.AzureDataStudio"
    ## Tencent
    Install-IfNotInstalled "Tencent.WeChat"
    Install-IfNotInstalled "Tencent.QQ"
    #Install-IfNotInstalled "SoftDeluxe.FreeDownloadManager"
    #Install-IfNotInstalled "VideoLAN.VLC"
    #Install-IfNotInstalled "OBSProject.OBSStudio"
    Install-IfNotInstalled "Git.Git"
    Install-IfNotInstalled "OpenJS.NodeJS"
    Install-IfNotInstalled "Postman.Postman"
    #Install-IfNotInstalled "7zip.7zip"
    #Install-IfNotInstalled "CPUID.CPU-Z"
    #Install-IfNotInstalled "WinDirStat.WinDirStat"
    #Install-IfNotInstalled "FastCopy.FastCopy"
    #Install-IfNotInstalled "DBBrowserForSQLite.DBBrowserForSQLite"
    Install-IfNotInstalled "Youdao.YoudaoNote"
    Install-IfNotInstalled "ZeroTier.ZeroTierOne"
    Install-IfNotInstalled "utools.utools"
    Install-IfNotInstalled "Postman.Postman"
    

    Install-StoreApp -storeAppId "9NBLGGH5R558" -wingetAppName "Microsoft To Do"
    Install-StoreApp -storeAppId "9MV0B5HZVK9Z" -wingetAppName "Xbox"
    Install-StoreApp -storeAppId "9wzdncrfjbh4" -wingetAppName "Microsoft Photos"
    Install-StoreApp -storeAppId "9nblggh4qghw" -wingetAppName "Microsoft Sticky Notes"
    Install-StoreApp -storeAppId "9wzdncrfhvqm" -wingetAppName "Mail and Calendar"
    Install-StoreApp -storeAppId "9ncbcszsjrsb" -wingetAppName "Spotify Music"
    Install-StoreApp -storeAppId "9mspc6mp8fm4" -wingetAppName "Microsoft Whiteboard"
    Install-StoreApp -storeAppId "9wzdncrfhvjl" -wingetAppName "OneNote for Windows 10"
    Install-StoreApp -storeAppId "9pf4kz2vn4w9" -wingetAppName "TranslucentTB"

    #Install-OtherSoftWare "https://res.u-tools.cn/version2/uTools-2.4.3.exe"
    Install-OtherSoftWare "https://www.mgnb.jp/download/MGNB.exe"
    Install-OtherSoftWare "https://github.com/AutoDarkMode/Windows-Auto-Night-Mode/releases/download/10.1.0.10/AutoDarkModeX_10.1.0.10.exe"
    #Install-OtherSoftWare "https://download.ydstatic.com/notewebsite/downloads/YNote.exe"
    #Install-OtherSoftWare "https://download.zerotier.com/dist/ZeroTierOne.msi"
    <#
    Write-Host "Configuring FDM..." -ForegroundColor Green
    cmd /c "taskkill.exe /IM fdm.exe /F"
    Remove-Item -Path "$env:LOCALAPPDATA\Softdeluxe" -Force -Recurse -ErrorAction SilentlyContinue
    Start-Process "$env:ProgramFiles\Softdeluxe\Free Download Manager\fdm.exe"
    Start-Sleep -Seconds 5
    cmd /c "taskkill.exe /IM fdm.exe /F"
    $fdmDbPath = "$env:LOCALAPPDATA\Softdeluxe\Free Download Manager\db.sqlite"
    Invoke-WebRequest -Uri "https://github.com/Anduin2017/configuration-script-win/raw/main/db.sqlite" -OutFile "$fdmDbPath"
    #>

    if (-not $(Get-Command git-lfs)) {
        winget install "GitHub.GitLFS" --source winget
    }
    else {
        Write-Host "Git LFS is already installed." -ForegroundColor Yellow
    }
    
    Write-Host "-----------------------------" -ForegroundColor Green
    Write-Host "        PART 3  - Terminal    " -ForegroundColor Green
    Write-Host "-----------------------------" -ForegroundColor Green

    Write-Host "Adding Git-Bash to environment variable..." -ForegroundColor Green
    [Environment]::SetEnvironmentVariable(
        "Path",
        [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine) + ";C:\Program Files\Git\bin",
        [EnvironmentVariableTarget]::Machine)

    Write-Host "Setting execution policy to remotesigned..." -ForegroundColor Green
    Set-ExecutionPolicy remotesigned

    Write-Host "Installing profile file..." -ForegroundColor Green
    if (!(Test-Path $PROFILE)) {
        Write-Host "Creating PROFILE..." -ForegroundColor Yellow
        New-Item -Path $PROFILE -ItemType "file" -Force
    }
    $profileContent = (New-Object System.Net.WebClient).DownloadString('https://gitee.com/guo_xiaohao/configuration-script-win/raw/main/PROFILE.ps1')
    Set-Content $PROFILE $profileContent
    . $PROFILE

    $OneDrivePath = "$env:USERPROFILE\OneDrive"
    Write-Host "OneDrive path is $OneDrivePath" -ForegroundColor Green
    Write-Host "Linking back SSH keys..." -ForegroundColor Green
    $oneDriveSshConfigPath = "$OneDrivePath\Storage\SSH\"
    $localSshConfigPath = "$HOME\.ssh\"
    $_ = Get-Content $oneDriveSshConfigPath\id_rsa.pub # Ensure file is available.
    cmd /c "rmdir $localSshConfigPath /q"
    cmd /c "mklink /d `"$localSshConfigPath`" `"$oneDriveSshConfigPath`""
    Write-Host "Testing SSH features..." -ForegroundColor Green
    Write-Host "yes" | ssh -o "StrictHostKeyChecking no" git@github.com

    Write-Host "Configuring git..." -ForegroundColor Green
    Write-Host "Setting git email to $email" -ForegroundColor Yellow
    Write-Host "Setting git name to $name" -ForegroundColor Yellow
    git config --global user.email $email
    git config --global user.name $name
    git config --global core.autocrlf true
    
    Write-Host "Linking back windows terminal configuration file..." -ForegroundColor Green
    $wtConfigPath = "$HOME\AppData\Local\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
    $onedriveConfigwt = "$OneDrivePath\Storage\WT\settings.json"
    $_ = Get-Content $onedriveConfigwt # Ensure file is available.
    cmd /c "del `"$wtConfigPath`""
    cmd /c "mklink `"$wtConfigPath`" `"$onedriveConfigwt`""
    <#  
    Write-Host "Configuring windows terminal context menu..." -ForegroundColor Green
    git clone https://github.com/lextm/windowsterminal-shell.git "$HOME\temp"
    pwsh -command "$HOME\temp\install.ps1 mini"
    Remove-Item $HOME\temp -Force -Recurse -Confirm:$false
    #>
    <#
    Write-Host "-----------------------------" -ForegroundColor Green
    Write-Host "        PART 4  - SDK    " -ForegroundColor Green
    Write-Host "-----------------------------" -ForegroundColor Green

    Write-Host "Setting up some node js global tools..." -ForegroundColor Green
    npm install --global npm@latest
    npm install --global node-static typescript @angular/cli yarn

    Write-Host "Setting up .NET environment variables..." -ForegroundColor Green
    [Environment]::SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Development", "Machine")
    [Environment]::SetEnvironmentVariable("DOTNET_PRINT_TELEMETRY_MESSAGE", "false", "Machine")
    [Environment]::SetEnvironmentVariable("DOTNET_CLI_TELEMETRY_OPTOUT", "1", "Machine")

    if (-not (Test-Path -Path "$env:APPDATA\Nuget\Nuget.config") -or $null -eq (Select-String -Path "$env:APPDATA\Nuget\Nuget.config" -Pattern "nuget.org")) {
        $config = "<?xml version=`"1.0`" encoding=`"utf-8`"?>`
    <configuration>`
      <packageSources>`
        <add key=`"nuget.org`" value=`"https://api.nuget.org/v3/index.json`" protocolVersion=`"3`" />`
        <add key=`"Microsoft Visual Studio Offline Packages`" value=`"C:\Program Files (x86)\Microsoft SDKs\NuGetPackages\`" />`
      </packageSources>`
      <config>`
        <add key=`"repositoryPath`" value=`"D:\CxCache`" />`
      </config>`
    </configuration>"
        Set-Content -Path "$env:APPDATA\Nuget\Nuget.config" -Value $config
    }
    else {
        Write-Host "Nuget config file already exists." -ForegroundColor Yellow
    }
    New-Item -Path "C:\Program Files (x86)\Microsoft SDKs\NuGetPackages\" -ItemType directory -Force

    Write-Host "Installing Github.com/microsoft/artifacts-credprovider..." -ForegroundColor Green
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/microsoft/artifacts-credprovider/master/helpers/installcredprovider.ps1'))
    dotnet tool install --global dotnet-ef --interactive
    dotnet tool update --global dotnet-ef --interactive

    Write-Host "Building some .NET projects to ensure you can develop..." -ForegroundColor Green
    git clone https://github.com/AiursoftWeb/Infrastructures.git "$HOME\source\repos\AiursoftWeb\Infrastructures"
    git clone https://github.com/AiursoftWeb/AiurVersionControl.git "$HOME\source\repos\AiursoftWeb\AiurVersionControl"
    git clone https://github.com/Anduin2017/Happiness-recorder.git "$HOME\source\repos\Anduin2017\Happiness-recorder"
    dotnet publish "$HOME\source\repos\Anduin2017\Happiness-recorder\JAI.csproj" -c Release -r win-x64 -o "$OneDrivePath\Storage\Tools\JAL"
    #>
    Write-Host "-----------------------------" -ForegroundColor Green
    Write-Host "        PART 5  - Desktop    " -ForegroundColor Green
    Write-Host "-----------------------------" -ForegroundColor Green

    Write-Host "Clearing recycle bin..." -ForegroundColor Green
    Write-Host "Recycle bin cleared on $driveLetter..."
    Clear-RecycleBin -DriveLetter $driveLetter -Force -Confirm

    Write-Host "Disabling rubbish Active Probing..." -ForegroundColor Green
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet\" -Name EnableActiveProbing -Value 0 -Force
    Write-Host "Disabled Active Probing."

    Write-Host "Clearing start up..." -ForegroundColor Green
    $startUp = $env:USERPROFILE + "\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\StartUp\*"
    Get-ChildItem $startUp
    Remove-Item -Path $startUp
    Get-ChildItem $startUp

    Write-Host "Uninsatll some Software..." -ForegroundColor Green
    winget uninstall MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy
    winget uninstall MicrosoftTeams_8wekyb3d8bbwe

    Write-Host "Remove rubbish 3D objects..." -ForegroundColor Green
    Remove-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}' -ErrorAction SilentlyContinue
    Write-Host "3D objects deleted."

    Write-Host "Setting Power Policy to ultimate..." -ForegroundColor Green
    powercfg /s e9a42b02-d5df-448d-aa00-03f14749eb61
    powercfg /list
    <#
    Write-Host "Enabling desktop icons..." -ForegroundColor Green
    cmd.exe /c "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu /v {20D04FE0-3AEA-1069-A2D8-08002B30309D} /t REG_DWORD /d 0 /f"
    cmd.exe /c "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel /v {20D04FE0-3AEA-1069-A2D8-08002B30309D} /t REG_DWORD /d 0 /f"
    cmd.exe /c "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu /v {59031a47-3f72-44a7-89c5-5595fe6b30ee} /t REG_DWORD /d 0 /f"
    cmd.exe /c "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel /v {59031a47-3f72-44a7-89c5-5595fe6b30ee} /t REG_DWORD /d 0 /f"
    cmd.exe /c "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu /v {645FF040-5081-101B-9F08-00AA002F954E} /t REG_DWORD /d 0 /f"
    cmd.exe /c "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel /v {645FF040-5081-101B-9F08-00AA002F954E} /t REG_DWORD /d 0 /f"
    cmd.exe /c "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu /v {F02C1A0D-BE21-4350-88B0-7367FC96EF3C} /t REG_DWORD /d 0 /f"
    cmd.exe /c "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel /v {F02C1A0D-BE21-4350-88B0-7367FC96EF3C} /t REG_DWORD /d 0 /f"
    #>
    $wallpaper = "$OneDrivePath\Pictures\Wallpaper\girl.jpg"
    if (Test-Path $wallpaper) {
        Write-Host "Setting wallpaper to $wallpaper..." -ForegroundColor Green
        Set-WallPaper -Image $wallpaper
        Write-Host "Set to: " (Get-Item "$OneDrivePath\Pictures\Wallpaper\girl.jpg").Name
    }

    Write-Host "Disable Sleep on AC Power..." -ForegroundColor Green
    Powercfg /Change monitor-timeout-ac 20
    Powercfg /Change standby-timeout-ac 0
    Write-Host "Monitor timeout set to 20."

    Write-Host "Enabling Chinese input method..." -ForegroundColor Green
    $UserLanguageList = New-WinUserLanguageList -Language zh-CN
    $UserLanguageList.Add("zh-CN")
    Set-WinUserLanguageList $UserLanguageList -Force
    $UserLanguageList | Format-Table -AutoSize

    Write-Host "Removing Bluetooth icons..." -ForegroundColor Green
    cmd.exe /c "reg add `"HKCU\Control Panel\Bluetooth`" /v `"Notification Area Icon`" /t REG_DWORD /d 0 /f"

    Write-Host "Disabling apps auto start..." -ForegroundColor Green
    cmd.exe /c "reg delete  HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v Wechat /f"
    cmd.exe /c "reg delete  HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v YNote /f"
    cmd.exe /c "reg delete  HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v cloudmusic /f"
    cmd.exe /c "reg delete  HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v `"Free Download Manager`" /f"

    Write-Host "Applying file explorer settings..." -ForegroundColor Green
    cmd.exe /c "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v HideFileExt /t REG_DWORD /d 0 /f"
    cmd.exe /c "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v AutoCheckSelect /t REG_DWORD /d 0 /f"
    cmd.exe /c "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v LaunchTo /t REG_DWORD /d 1 /f"

    Write-Host "Setting Time zone..." -ForegroundColor Green
    Set-TimeZone -Name "China Standard Time"
    Write-Host "Time zone set to China Standard Time."

    Write-Host "Syncing time..." -ForegroundColor Green
    net stop w32time
    net start w32time
    w32tm /resync /force
    w32tm /query /status
    <#
    Write-Host "Setting mouse speed..." -ForegroundColor Green
    cmd.exe /c "reg add `"HKCU\Control Panel\Mouse`" /v MouseSensitivity /t REG_SZ /d 6 /f"
    cmd.exe /c "reg add `"HKCU\Control Panel\Mouse`" /v MouseSpeed /t REG_SZ /d 0 /f"
    cmd.exe /c "reg add `"HKCU\Control Panel\Mouse`" /v MouseThreshold1 /t REG_SZ /d 0 /f"
    cmd.exe /c "reg add `"HKCU\Control Panel\Mouse`" /v MouseThreshold2 /t REG_SZ /d 0 /f"
    Write-Host "Mouse speed changed. Will apply next reboot." -ForegroundColor Yellow
    #>
    Write-Host "Pin repos to quick access..." -ForegroundColor Green
    $load_com = new-object -com shell.application
    $load_com.Namespace("$env:USERPROFILE\source\repos").Self.InvokeVerb("pintohome")
    Write-Host "Repos folder are pinned to file explorer."

    Write-Host "Enabling dark theme..." -ForegroundColor Green
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name AppsUseLightTheme -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name SystemUsesLightTheme -Value 0
    Write-Host "Dark theme enabled."

    Write-Host "Cleaning desktop..." -ForegroundColor Green
    Remove-Item $HOME\Desktop\* -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item "C:\Users\Public\Desktop\*" -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue

    Write-Host "Resetting desktop..." -ForegroundColor Yellow
    Stop-Process -Name explorer -Force
    Write-Host "Desktop cleaned."

    Write-Host "-----------------------------" -ForegroundColor Green
    Write-Host "        PART 6  - Security    " -ForegroundColor Green
    Write-Host "-----------------------------" -ForegroundColor Green

    $networkProfiles = Get-NetConnectionProfile
    foreach ($networkProfile in $networkProfiles) {
        Write-Host "Setting network $($networkProfile.Name) to home network to enable more features..." -ForegroundColor Green
        Write-Host "This is dangerous because your roommates may detect your device is online." -ForegroundColor Yellow
        Set-NetConnectionProfile -Name $networkProfile.Name -NetworkCategory Private
    }

    Write-Host "Setting UAC..." -ForegroundColor Green
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name "ConsentPromptBehaviorAdmin" -Value 5
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name "PromptOnSecureDesktop" -Value 1

    Write-Host "Enable Remote Desktop..." -ForegroundColor Green
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\" -Name "fDenyTSConnections" -Value 0
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\" -Name "UserAuthentication" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

    # Upgrade all.
    Write-Host "Checking for final app upgrades..." -ForegroundColor Green
    winget upgrade --all --source winget

    Write-Host "Press the [C] key to continue to steps which requires reboot."
    $pressedKey = Read-Host
    Write-Host "You pressed: $($pressedKey)"

    if ($pressedKey -eq 'c') {
        Write-Host "Reseting WS..." -ForegroundColor Green
        WSReset.exe
    
        Write-Host "Scanning missing dlls..." -ForegroundColor Green
        sfc /scannow
        Write-Host y | chkdsk "$($driveLetter):" /f /r /x

        Write-Host "Checking for windows updates..." -ForegroundColor Green
        Install-Module -Name PSWindowsUpdate -Force
        Write-Host "Installing updates... (Computer will reboot in minutes...)" -ForegroundColor Green
        Get-WindowsUpdate -AcceptAll -Install -ForceInstall -AutoReboot

        cmd.exe /c "netsh winsock reset catalog"
        cmd.exe /c "netsh int ip reset reset.log"
        cmd.exe /c "ipconfig /flushdns"
        cmd.exe /c "ipconfig /registerdns"
        cmd.exe /c "route /f"
        cmd.exe /c "sc config FDResPub start=auto"
        cmd.exe /c "sc config fdPHost start=auto"
        cmd.exe /c "shutdown -r -t 70"
    }

    Do-Next

}
