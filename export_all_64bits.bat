REM Place this and Export-ClientCertificates.ps1 into the jailbreak root folder (where the other .bat files are located)
REM Execute this to export all certficates, each to one file with 12345 as password
REM you can use later Import-AllPfx.ps1 from this same repo to import all the pfx at once

cd %~dp0\binaries
@jailbreak64.exe powershell -exec bypass ..\Export-ClientCertificates.ps1 %*
