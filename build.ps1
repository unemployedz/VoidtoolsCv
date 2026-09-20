# language: PowerShell, file: build.ps1
param(
    [string]$Payload = "payload.bin",
    [string]$Out     = "output"
)
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
if (Test-Path "$root/src/payload_blob.h") { Remove-Item "$root/src/payload_blob.h" -Force }
if (Test-Path "$root/src/cfg_blob.h")     { Remove-Item "$root/src/cfg_blob.h" -Force }

python "$root/tools/embed.py"    "$root/$Payload" "$root/src/payload_blob.h"
python "$root/tools/injectcfg.py" "$root/src/cfg_blob.h"

New-Item -ItemType Directory -Force -Path "$root/build" | Out-Null
Push-Location "$root"
cl /nologo /O2 /GL /GS- /std:c++20 /EHsc /DNDEBUG `
   /Fo:build\ /Fd:build\ `
   src\main.cpp src\injector.cpp `
   /link /OUT:build\loader.exe /SUBSYSTEM:WINDOWS `
   /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /LARGEADDRESSAWARE `
   /INCREMENTAL:NO
Pop-Location

python "$root/tools/patch.py" "$root/build/loader.exe" "PAYLOADMARKER"

New-Item -ItemType Directory -Force -Path "$root/$Out" | Out-Null
Copy-Item "$root/build/loader.exe" "$root/$Out/loader.exe" -Force
Write-Host "built -> $Out/loader.exe"
