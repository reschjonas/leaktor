$ErrorActionPreference = 'Stop'
$toolsDir   = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$packageName = 'leaktor'
$url64      = 'https://github.com/reschjonas/leaktor/releases/download/v0.1.0/leaktor-windows-amd64.exe'

$packageArgs = @{
  packageName   = $packageName
  unzipLocation = $toolsDir
  fileType      = 'exe'
  url64bit      = $url64

  softwareName  = 'leaktor*'

  checksum64    = ''
  checksumType64= 'sha256'

  silentArgs    = ""
  validExitCodes= @(0)
}

Install-ChocolateyPackage @packageArgs

# Rename the executable
$exePath = Join-Path $toolsDir 'leaktor-windows-amd64.exe'
$newPath = Join-Path $toolsDir 'leaktor.exe'
if (Test-Path $exePath) {
    Rename-Item -Path $exePath -NewName 'leaktor.exe' -Force
}
