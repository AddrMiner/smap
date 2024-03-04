

$npcap = "npcap-1.79"
$npcap_sdk = "npcap-sdk-1.13"
$defaultInstallPath = "${env:USERPROFILE}\smap"
$resourceFolder = @(".\\block_list",".\\probe_modules_payload")
$libPath = "C:\Users\$env:UserName\.rustup\toolchains\stable-x86_64-pc-windows-gnu\lib\rustlib\x86_64-pc-windows-gnu\lib"
if (-not (Test-Path $libPath)) {
    Write-Error "Target lib path '$libPath' does not exist"
    exit 1
}

# user input
$installPath = Read-Host "Enter install path or press Enter for default($defaultInstallPath)"
if ($installPath -eq "") {
    $installPath = $defaultInstallPath
}
if (-not (Test-Path $installPath)) {
    New-Item -ItemType Directory -Path $installPath
}
Write-Output "smap will be installed to $installPath"

# install temp dir
$tempDir = Join-Path $env:TEMP "installNpcap" 
New-Item -ItemType Directory -Path $tempDir

$npcap_installed = Read-Host "Have Npcap been installed and SDK configured(y or ..)"
if ($npcap_installed -ne "y") {

    # 1. Download Npcap and install
    $url_npcap = "https://npcap.com/dist/$npcap.exe"
    $outputPath = Join-Path $tempDir "$npcap.exe"
    Invoke-WebRequest -Uri $url_npcap -OutFile $outputPath
    Start-Process -FilePath $outputPath -Wait

    # 2. Get system architecture
    $x64 = [environment]::Is64BitOperatingSystem
    $ARM64 = [environment]::IsArm64OperatingSystem

    # 3. Npcap SDK
    $url_npcap_sdk = "https://npcap.com/dist/$npcap_sdk.zip"
    $sdkZip = Join-Path $tempDir "$npcap_sdk.zip"
    $sdkFile = Join-Path $tempDir $npcap_sdk
    Invoke-WebRequest -Uri $url_npcap_sdk -OutFile $sdkZip
    Expand-Archive -Path $sdkZip -DestinationPath $sdkFile

    if ($x64) {
        Copy-Item "$sdkFile\Lib\x64\*" $libPath
    }
    elseif ($ARM64) {
        Copy-Item "$sdkFile\Lib\ARM64\*" $libPath
    }
    else {
        Copy-Item "$sdkFile\Lib\Packet.lib" $libPath
        Copy-Item "$sdkFile\Lib\wpcap.lib" $libPath
    }
}

# 4. Install with cargo
cargo install --path . --root $installPath

# 5. copy resource folder
$keep_res_files = Read-Host "Do you need to keep the resource files (please confirm that all resource files are working properly) (y or ..)"
if ($keep_res_files -ne "y") {
    Copy-Item -Path $resourceFolder -Destination $installPath -Recurse -Force
}

# 6. clear
Remove-Item $tempDir -Recurse -Force
Remove-Item .\target -Recurse -Force

# 7. Add cargo bin path to PATH
$cargoBinPath = "$installPath\bin"
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not $userPath.Contains($cargoBinPath)) {
    [Environment]::SetEnvironmentVariable("Path", $userPath + ";$cargoBinPath", "User")
    Write-Output "Please close the current terminal window and open a new terminal"
}