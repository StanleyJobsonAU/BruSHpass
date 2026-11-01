param(
    [string]$VcpkgRoot = '',
    [string]$Zig = '',
    [string]$LinuxOpenSsl = ''
)
$ErrorActionPreference = 'Stop'
$projectPath = Split-Path -Parent $PSScriptRoot
if (-not $VcpkgRoot) { $VcpkgRoot = Join-Path $projectPath '.native-deps\vcpkg' }
if (-not $Zig) { $Zig = Join-Path $projectPath '.native-deps\zig-x86_64-windows-0.15.2\zig.exe' }
if (-not $LinuxOpenSsl) { $LinuxOpenSsl = Join-Path $projectPath '.native-deps\openssl-linux' }
$cmake = (Get-ChildItem (Join-Path $VcpkgRoot 'downloads\tools\cmake-*-windows') -Recurse -Filter cmake.exe | Select-Object -First 1).FullName
if (-not $cmake) { $cmake = (Get-Command cmake -ErrorAction Stop).Source }
$python = Join-Path $projectPath '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) { $python = (Get-Command python -ErrorAction Stop).Source }
foreach ($requiredPath in @($Zig, (Join-Path $LinuxOpenSsl 'libcrypto.a'), (Join-Path $LinuxOpenSsl 'libssl.a'))) {
    if (-not (Test-Path -LiteralPath $requiredPath)) { throw "Missing build dependency: $requiredPath" }
}
function Check-NativeExit { if ($LASTEXITCODE -ne 0) { throw "Native build command failed with exit code $LASTEXITCODE" } }
Push-Location $projectPath
try {
    $toolchain = Join-Path $VcpkgRoot 'scripts\buildsystems\vcpkg.cmake'
    & $cmake -S . -B build/windows-template -G 'Visual Studio 17 2022' -A x64 "-DCMAKE_TOOLCHAIN_FILE=$toolchain" -DVCPKG_TARGET_TRIPLET=x64-windows-static -DBP_CLIENT_TEMPLATE=ON
    Check-NativeExit
    & $cmake --build build/windows-template --config Release --parallel 4
    Check-NativeExit
    New-Item -ItemType Directory -Force build/linux-template,build/linux-server,dist/BruSHpass-release | Out-Null
    $sources = @('native/main.c','native/platform.c','native/identity.c','native/protocol.c','native/export.c','native/execute.c')
    $crossFlags = @('cc','-target','x86_64-linux-musl','-static','-s','-O2','-Wall','-Wextra','-Wpedantic','-Inative',"-I$LinuxOpenSsl/include")
    $crossLibs = @("$LinuxOpenSsl/libssl.a","$LinuxOpenSsl/libcrypto.a",'-pthread','-ldl')
    & $Zig @crossFlags -DBP_CLIENT_TEMPLATE @sources @crossLibs -o build/linux-template/brushpass
    Check-NativeExit
    $winTemplate = Join-Path $projectPath 'build/windows-template/Release/BruSHpass.exe'
    $linuxTemplate = Join-Path $projectPath 'build/linux-template/brushpass'
    & $cmake -S . -B build/windows-server -G 'Visual Studio 17 2022' -A x64 "-DCMAKE_TOOLCHAIN_FILE=$toolchain" -DVCPKG_TARGET_TRIPLET=x64-windows-static "-DBP_TEMPLATE_WINDOWS=$winTemplate" "-DBP_TEMPLATE_LINUX=$linuxTemplate"
    Check-NativeExit
    & $cmake --build build/windows-server --config Release --parallel 4
    Check-NativeExit
    & $python tools/embed_templates.py $winTemplate $linuxTemplate build/linux-server/embedded_templates.c
    Check-NativeExit
    & $Zig @crossFlags -DBP_WITH_TEMPLATES @sources build/linux-server/embedded_templates.c @crossLibs -o build/linux-server/BruSHpass
    Check-NativeExit
    & build/windows-server/Release/BruSHpass.exe --self-test
    Check-NativeExit
    # Stage replacements so NTFS records the requested capitalization as well.
    Copy-Item -LiteralPath build/windows-server/Release/BruSHpass.exe -Destination dist/BruSHpass-release/_server-new.exe
    Copy-Item -LiteralPath build/linux-server/BruSHpass -Destination dist/BruSHpass-release/_server-new-linux
    foreach ($oldOutput in @('dist/BruSHpass-release/BruSHpass.exe','dist/BruSHpass-release/BruSHpass')) {
        if (Test-Path -LiteralPath $oldOutput) { Remove-Item -LiteralPath $oldOutput }
    }
    Move-Item -LiteralPath dist/BruSHpass-release/_server-new.exe -Destination dist/BruSHpass-release/BruSHpass.exe
    Move-Item -LiteralPath dist/BruSHpass-release/_server-new-linux -Destination dist/BruSHpass-release/BruSHpass
    New-Item -ItemType Directory -Force dist/BruSHpass-release/templates | Out-Null
    Copy-Item -LiteralPath $winTemplate -Destination dist/BruSHpass-release/templates/windows-x64.exe
    Copy-Item -LiteralPath $linuxTemplate -Destination dist/BruSHpass-release/templates/linux-x64
    Get-FileHash dist/BruSHpass-release/BruSHpass.exe,dist/BruSHpass-release/BruSHpass -Algorithm SHA256 | Format-Table Path,Hash
} finally { Pop-Location }
