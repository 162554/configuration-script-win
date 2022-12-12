
function RemoveUWP {
    param (
        [string]$name
    )

    Write-Host "Removing UWP $name..." -ForegroundColor Green
    Get-AppxPackage $name | Remove-AppxPackage
    Get-AppxPackage $name | Remove-AppxPackage -AllUsers
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

Write-Host "-----------------------------" -ForegroundColor Green
Write-Host "        PART 2  - Install    " -ForegroundColor Green
Write-Host "-----------------------------" -ForegroundColor Green

if (-not(Get-IsElevated)) { 
    throw "Please run this script as an administrator" 
}

# Install Winget
if (-not $(Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Host "Installing WinGet..." -ForegroundColor Green
    Start-Process "ms-appinstaller:?source=https://aka.ms/getwinget"

    Install-StoreApp -storeAppId "9NBLGGH4NNS1" -wingetAppName "App Installer"

    while(-not $(Get-Command winget -ErrorAction SilentlyContinue))
    {
        Write-Host "Winget is still not found!" -ForegroundColor Yellow
        Start-Sleep -Seconds 5
    }
}

Write-Host "Triggering Store to upgrade all apps..." -ForegroundColor Green
# $namespaceName = "root\cimv2\mdm\dmmap"
# $className = "MDM_EnterpriseModernAppManagement_AppManagement01"
# $wmiObj = Get-WmiObject -Namespace $namespaceName -Class $className
# $wmiObj.UpdateScanMethod() | Format-Table -AutoSize

if ("$(winget list --id Microsoft.VisualStudioCode --source winget)".Contains("--")) { 
     Write-Host "Microsoft.VisualStudioCode is already installed!" -ForegroundColor Green
}
else {
    Write-Host "Attempting to download Microsoft VS Code..." -ForegroundColor Green
    winget install --exact --id Microsoft.VisualStudioCode --scope Machine --interactive --source winget
}

Install-IfNotInstalled "EclipseAdoptium.Temurin.8.JRE"
Install-IfNotInstalled "Tencent.WeChat"
Install-IfNotInstalled "Python.Python.3"
Install-IfNotInstalled "GoLang.Go"
Install-IfNotInstalled "SoftDeluxe.FreeDownloadManager"
Install-IfNotInstalled "VideoLAN.VLC"
Install-IfNotInstalled "Telegram.TelegramDesktop"
Install-IfNotInstalled "OBSProject.OBSStudio"
Install-IfNotInstalled "Git.Git"
Install-IfNotInstalled "gerardog.gsudo"
Install-IfNotInstalled "OpenJS.NodeJS"
Install-IfNotInstalled "Postman.Postman"
Install-IfNotInstalled "7zip.7zip"
Install-IfNotInstalled "CPUID.CPU-Z"
Install-IfNotInstalled "WinDirStat.WinDirStat"
Install-IfNotInstalled "FastCopy.FastCopy"
Install-IfNotInstalled "DBBrowserForSQLite.DBBrowserForSQLite"
Install-IfNotInstalled "CrystalDewWorld.CrystalDiskInfo"
Install-IfNotInstalled "Google.Chrome"
Install-IfNotInstalled "JetBrains.IntelliJIDEA.Ultimate"
Install-IfNotInstalled "Notion.Notion"
Install-IfNotInstalled "TortoiseSVN.TortoiseSVN"
Install-IfNotInstalled "Nextcloud.NextcloudDesktop"
Install-IfNotInstalled "OpenVPNTechnologies.OpenVPN"
Install-IfNotInstalled "NetEase.CloudMusic"
Install-IfNotInstalled "Armin2208.WindowsAutoNightMode"
Install-IfNotInstalled "ZeroTier.ZeroTierOne"
Install-IfNotInstalled "Yuanli.uTools"
Install-IfNotInstalled "Fndroid.ClashForWindows"
Install-IfNotInstalled "Tencent.TIM"
Install-IfNotInstalled "CrystalDiskMark8_is1"
Install-IfNotInstalled "Microsoft.PowerShell"
Install-IfNotInstalled "notepad++"
Install-IfNotInstalled "dbeaver.dbeaver"


#Install-StoreApp -storeAppId "9N0DX20HK701" -wingetAppName "Windows Terminal"
Install-StoreApp -storeAppId "9nblggh4qghw" -wingetAppName "Microsoft Sticky Notes"
Install-StoreApp -storeAppId "9wzdncrfhvqm" -wingetAppName "Mail and Calendar"
Install-StoreApp -storeAppId "9mspc6mp8fm4" -wingetAppName "Microsoft Whiteboard"
Install-StoreApp -storeAppId "9wzdncrfhvjl" -wingetAppName "OneNote for Windows 10"
Install-StoreApp -storeAppId "9N4D0MSMP0PT" -wingetAppName "VP9 Video Extensions"
Install-StoreApp -storeAppId "9N4D0MSMP0PT" -wingetAppName "AV1 Video Extension"
Install-StoreApp -storeAppId "9NM8N7DQ3Z5F" -wingetAppName "WinDynamicDesktop"
Install-StoreApp -storeAppId "9PKTQ5699M62" -wingetAppName "iCloud"

# icloud 

RemoveUWP Microsoft.MSPaint
RemoveUWP Microsoft.Microsoft3DViewer


Write-Host "Cleaning desktop..." -ForegroundColor Green
Remove-Item $HOME\Desktop\* -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item "C:\Users\Public\Desktop\*" -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue

