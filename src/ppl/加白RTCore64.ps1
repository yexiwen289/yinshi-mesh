# RTCore64.sys / PPLcontrol.exe 杀软加白脚本（需管理员运行）
# 用法：右键"使用 PowerShell 运行"，或在管理员 PowerShell 里执行本文件
# 支持两条加白路径：
#   1. 目录白名单（最彻底）：整个 pplwork 目录排除
#   2. 文件白名单：RTCore64.sys / PPLcontrol.exe

$ErrorActionPreference = 'Continue'

$targets = @('C:\pplwork')
$files = @('C:\pplwork\RTCore64.sys', 'C:\pplwork\PPLcontrol.exe')

Write-Host "=== 杀软加白 RTCore64.sys ==="

# ---- Windows Defender ----
if (Get-Command Add-MpPreference -ErrorAction SilentlyContinue) {
    Write-Host "[Defender] 发现 Windows Defender"
    try {
        Add-MpPreference -ExclusionPath $targets -ErrorAction Stop
        Write-Host "[Defender] 目录白名单已添加: $($targets -join ', ')"
        Add-MpPreference -ExclusionFile $files -ErrorAction SilentlyContinue
        Write-Host "[Defender] 文件白名单已添加"
    } catch {
        Write-Host "[Defender] 加白失败（需要管理员权限）: $_"
    }
} else {
    Write-Host "[Defender] 未启用，跳过"
}

# ---- 360 ----
$z360 = Get-Process 360tray, 360safe, 360sd -ErrorAction SilentlyContinue
if ($z360) {
    Write-Host "[360] 检测到 360 在运行"
    Write-Host "[360] 360 不支持命令行加白，请手动操作："
    Write-Host "      360安全卫士 -> 木马查杀 -> 信任区 -> 添加目录 -> C:\pplwork"
} else {
    Write-Host "[360] 未检测到，跳过"
}

# ---- 火绒 ----
$hr = Get-Process HipsTray, wsctrl, usysdiag -ErrorAction SilentlyContinue
if ($hr) {
    Write-Host "[火绒] 检测到火绒在运行"
    Write-Host "[火绒] 火绒不支持命令行加白，请手动操作："
    Write-Host "      火绒安全软件 -> 信任区 -> 添加 -> C:\pplwork"
} else {
    Write-Host "[火绒] 未检测到，跳过"
}

# ---- 验证 Defender 白名单 ----
if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
    $excl = (Get-MpPreference).ExclusionPath
    if ($excl) {
        Write-Host "`n[验证] 当前 Defender 目录白名单:"
        $excl | ForEach-Object { Write-Host "  - $_" }
    }
}

Write-Host "`n=== 完成 ==="
