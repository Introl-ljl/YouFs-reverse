# apk-reverse -- project-local environment (PowerShell)
#
# Scope: the CURRENT SHELL ONLY. This file touches nothing under $HOME, $DSH_HOME
# or any other global location; it only points the apk-reverse scripts at this
# project's own tools\ directory.
#
# Usage (dot-source it so the variables survive the command):
#     . .\tools\env.ps1
#
# Put project-local toolchain drops in .\tools\ (and runnable .jars in .\tools\jars\).
# Nothing here needs to be global for the skill to work.

$ApkRevRoot  = Split-Path -Parent $PSScriptRoot
$ApkRevTools = Join-Path $ApkRevRoot 'tools'
$ApkRevJars  = Join-Path $ApkRevTools 'jars'

New-Item -ItemType Directory -Force -Path $ApkRevJars | Out-Null

# os.pathsep-separated directories the skill's scripts probe for executables
# (adb, apktool, jadx, frida, rizin, readelf, ...).
$env:APKREV_TOOLS = $ApkRevTools

# Directory doctor.py searches for runnable Java tooling
# (uber-apk-signer.jar, baksmali/smali/dexlib2 jars, ...).
$env:APKREV_JARS = $ApkRevJars

# smali/baksmali/dexlib2 classpath read by smtool.py. Left unset if the caller
# already provided one; otherwise fall back to this project's jar directory.
if (-not $env:APK_REVERSE_SMALI_CP) { $env:APK_REVERSE_SMALI_CP = $ApkRevJars }

# Make project-local executables reachable in this shell as well, so a script
# that shells out by bare name still finds them before anything global.
$CandidateDirs = @(
    $ApkRevTools,
    $ApkRevJars,
    (Join-Path $ApkRevTools 'platform-tools'),
    (Join-Path $ApkRevTools 'bin'),
    (Join-Path $ApkRevTools 'cmdline-tools\latest\bin'),
    (Join-Path $ApkRevTools 'build-tools')
)
foreach ($d in $CandidateDirs) {
    if (-not (Test-Path $d)) { continue }
    if (($env:PATH -split ';') -notcontains $d) {
        $env:PATH = "$d;$env:PATH"
    }
}

Write-Host '[apk-reverse] project-local env loaded (no global state changed)'
Write-Host "  APKREV_TOOLS         = $env:APKREV_TOOLS"
Write-Host "  APKREV_JARS          = $env:APKREV_JARS"
Write-Host "  APK_REVERSE_SMALI_CP = $env:APK_REVERSE_SMALI_CP"
Write-Host "  skill                = .\.agents\skills\apk-reverse"
