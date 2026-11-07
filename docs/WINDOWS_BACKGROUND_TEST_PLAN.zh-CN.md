# Windows 10 / 11 无窗口采集测试方案

适用：本次窗口修复的 Windows amd64 测试包。请分别在 Windows 10 经典控制台和 Windows 11 上验证。测试包内 `toktrail.exe`、`toktrail-background.exe` 是产品文件；`toktrail-background-probe.exe` 仅用于本地测试，不放入正式安装目录。

本地测试包不是正式签名发布。正式升级应使用新版本的完整 bootstrap 安装器；旧版内置 upgrader 不认识新增 launcher manifest 字段，会拒绝解析。安装新文件后，已有任务需要显式执行 `service refresh`，只换 exe 不会改旧任务的启动动作。

## 1. 先做隔离测试：不绑定、不上传、不读取真实工具目录

将测试 ZIP 解压，在 PowerShell 切换到解压目录，执行：

```powershell
$testDir = (Get-Location).Path
$helper = Join-Path $testDir 'toktrail-background.exe'
$probe = Join-Path $testDir 'toktrail-background-probe.exe'
if (!(Test-Path -LiteralPath $helper) -or !(Test-Path -LiteralPath $probe)) {
  throw '请先切换到测试包解压目录'
}
$sandboxState = Join-Path $env:TEMP ('TokTrail Windowless 测试 ' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $sandboxState | Out-Null
$probeArgs = '--collector "{0}" --state-dir "{1}"' -f $probe, $sandboxState
$p = Start-Process -FilePath $helper -ArgumentList $probeArgs -Wait -PassThru
$p.ExitCode
Get-Content -LiteralPath (Join-Path $sandboxState 'probe.json')
Get-Content -LiteralPath (Join-Path $sandboxState 'logs\periodic.out.log')
Get-Content -LiteralPath (Join-Path $sandboxState 'logs\periodic.err.log')
```

预期：

- 全程没有额外黑窗口或窗口闪现，原 PowerShell 窗口正常保留。
- `ExitCode` 为 **7**：这是探针故意返回的值，用于证明启动器等待子进程并转发退出码，并不表示本测试失败。
- `probe.json` 中 `consoleHandle` 为 **0**，`pid` 大于 0。
- 两个日志分别包含 `WINDOWLESS-PROBE stdout` 和 `WINDOWLESS-PROBE stderr`。
- 错误日志还应有启动、结束和退出码的生命周期标记。

记录 Windows 版本及 PowerShell 版本：

```powershell
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber
$PSVersionTable.PSVersion
```

## 2. 日志轮转（仍仅使用隔离探针）

```powershell
Set-Content -LiteralPath (Join-Path $sandboxState 'probe-output-bytes.txt') -Value '1572864' -Encoding ASCII
$p = Start-Process -FilePath $helper -ArgumentList $probeArgs -Wait -PassThru
$p.ExitCode
Get-ChildItem -LiteralPath (Join-Path $sandboxState 'logs') | Select-Object Name, Length
Remove-Item -LiteralPath (Join-Path $sandboxState 'probe-output-bytes.txt')
```

预期：退出码仍为 7，没有新窗口。输出、错误日志各自按约 1 MiB 上限轮转，只保留当前文件及 `.1` 一代备份，不无限增长。这里只生成固定字母 `P`，没有真实对话或凭证内容。

## 3. 强制结束启动器时，子进程也必须结束

此步骤只终止上面的隔离探针，不能换成正在采集真实数据的 collector。

```powershell
Set-Content -LiteralPath (Join-Path $sandboxState 'probe-delay-ms.txt') -Value '30000' -Encoding ASCII
Remove-Item -LiteralPath (Join-Path $sandboxState 'probe.json') -ErrorAction SilentlyContinue
$parent = Start-Process -FilePath $helper -ArgumentList $probeArgs -PassThru
$limit = (Get-Date).AddSeconds(10)
$probeInfo = $null
while ($null -eq $probeInfo) {
  if ((Get-Date) -gt $limit) { throw '探针未启动，请查看隔离日志' }
  try {
    $candidate = Get-Content -LiteralPath (Join-Path $sandboxState 'probe.json') -Raw -ErrorAction Stop | ConvertFrom-Json
    if ($candidate.pid -gt 0) { $probeInfo = $candidate }
  } catch { }
  if ($null -eq $probeInfo) { Start-Sleep -Milliseconds 100 }
}
# 给启动器完成 Job Object 管理留出时间；此处不会读取真实 state。
Start-Sleep -Seconds 1
Stop-Process -Id $parent.Id -Force
Start-Sleep -Seconds 2
Get-Process -Id $probeInfo.pid -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $sandboxState 'probe-delay-ms.txt')
```

预期：最后一条 `Get-Process` 没有输出；没有遗留探针进程，没有黑窗口。如果仍有进程，记录其 PID 并报告，不通过此项验收。

## 4. 将测试版放入已有安装，迁移原任务

确认隔离测试通过后再操作已有安装。使用运行 WorkBuddy / Cursor 的同一 Windows 账户；不需要为此改成 SYSTEM 或保存账户密码。

### 4.1 确认原任务和 state

```powershell
$binDir = Join-Path $env:USERPROFILE '.toktrail\bin'
$exe = Join-Path $binDir 'toktrail.exe'
$state = if ($env:TOKTRAIL_HOME) { $env:TOKTRAIL_HOME } else { Join-Path $env:APPDATA 'toktrail' }
& $exe version
$tasks = @(Get-ScheduledTask -TaskName 'TokTrailCollector-*' | Where-Object {
  @($_.Actions | Where-Object { $_.Arguments -and $_.Arguments.IndexOf($state, [StringComparison]::OrdinalIgnoreCase) -ge 0 }).Count -gt 0
})
$tasks | Select-Object TaskName, State, @{n='Execute';e={$_.Actions.Execute}}, @{n='Arguments';e={$_.Actions.Arguments}}
if ($tasks.Count -ne 1) { throw '候选任务不是唯一一个，请明确要测试的 task 和 state 后再继续' }
$taskName = $tasks[0].TaskName
```

核对显示的 collector/state 确实属于当前安装。自定义安装目录或 state 时，先修正 `$binDir` / `$state`。不要把自定义 state 的任务迁移到另一个 state。

### 4.2 备份并暂停自动触发

```powershell
$backup = Join-Path $env:USERPROFILE ('Desktop\TokTrail-windowless-backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $backup | Out-Null
Export-ScheduledTask -TaskName $taskName | Out-File -LiteralPath (Join-Path $backup 'task-before.xml') -Encoding Unicode
Copy-Item -LiteralPath $exe -Destination (Join-Path $backup 'toktrail.exe')
$oldHelper = Join-Path $binDir 'toktrail-background.exe'
if (Test-Path -LiteralPath $oldHelper) { Copy-Item -LiteralPath $oldHelper -Destination (Join-Path $backup 'toktrail-background.exe') }
$wasEnabled = (Get-ScheduledTask -TaskName $taskName).Settings.Enabled
Disable-ScheduledTask -TaskName $taskName | Out-Null
Get-ScheduledTask -TaskName $taskName | Select-Object TaskName, State
```

如果任务还在 Running，等待本轮结束再替换文件。禁用触发不等于终止正在运行的采集。

### 4.3 替换两份产品 exe 并预览迁移

```powershell
Copy-Item -LiteralPath (Join-Path $testDir 'toktrail.exe') -Destination $exe -Force
Copy-Item -LiteralPath (Join-Path $testDir 'toktrail-background.exe') -Destination $oldHelper -Force
& $exe version
$beforeHashes = @('device.json','grants.json') | ForEach-Object {
  $path = Join-Path $state $_
  if (Test-Path -LiteralPath $path) { Get-FileHash -LiteralPath $path -Algorithm SHA256 }
}
& $exe service refresh --state-dir $state --dry-run
```

预期预览 XML 中：

- `Command` 指向同目录的 `toktrail-background.exe`。
- 参数是 `--collector "原 toktrail.exe 路径" --state-dir "原 state 路径"`。
- 账户仍为原 SID，`InteractiveToken`、`LeastPrivilege` 以及触发周期保持原值。
- 此时只是预览，尚未修改原任务。

如果任一复制失败，先恢复备份的产品文件，不继续迁移。

### 4.4 执行迁移、检查保留状态和幂等

```powershell
& $exe service refresh --state-dir $state
if ($LASTEXITCODE -ne 0) { throw '任务迁移失败，请保留输出排查' }
& $exe service refresh --state-dir $state
if ($LASTEXITCODE -ne 0) { throw '重复迁移失败' }
$afterHashes = @('device.json','grants.json') | ForEach-Object {
  $path = Join-Path $state $_
  if (Test-Path -LiteralPath $path) { Get-FileHash -LiteralPath $path -Algorithm SHA256 }
}
Compare-Object $beforeHashes $afterHashes -Property Path,Hash
Get-ScheduledTask -TaskName $taskName | Format-List TaskName, Principal, Triggers, Actions, Settings
& $exe doctor --state-dir $state
```

预期：

- 两次 refresh 都成功，显示 `background=true`；只有原来的一个 task。
- `Compare-Object` 没有差异（没有重新绑定或修改来源授权）。
- task 名称、账户、间隔、state 路径均未变化；现在 Action 使用后台 helper。
- 因测试中禁用了触发，迁移后也应保持禁用；这证明没有擅自更改任务设置。
- doctor 的 binary 身份正确，background 检查为 ok；原有来源的其他告警单独判断。

## 5. 真实任务运行与手动 CLI

```powershell
# 先启用任务，运行一次；完成测试后可按原 $wasEnabled 状态恢复。
Enable-ScheduledTask -TaskName $taskName | Out-Null
Start-ScheduledTask -TaskName $taskName
Get-ScheduledTask -TaskName $taskName | Select-Object TaskName, State
Get-ScheduledTaskInfo -TaskName $taskName | Select-Object LastRunTime, LastTaskResult, NextRunTime
Get-Content -LiteralPath (Join-Path $state 'logs\periodic.err.log') -Tail 30
Get-Content -LiteralPath (Join-Path $state 'logs\periodic.out.log') -Tail 10
```

预期：

- 保持桌面可见，全程没有额外黑窗口或闪现。
- 运行结束后 task 不再 Running，helper 和对应 collector 子进程都退出。
- 网络和授权正常、没有其他采集错误时，LastTaskResult 为 0。
- 若非 0，日志必须能看到与之对应的错误或退出码；不能把启动成功当作采集成功。
- 有新用量时服务器收到数据；没有新用量时空扫描成功也合理。

手动 CLI 另开 PowerShell 执行：

```powershell
& $exe periodic --state-dir $state --verbose
& $exe doctor --state-dir $state
```

预期手动输出仍可见。手动命令若与定时任务重叠，可报告 busy；应先等定时任务结束再重试。经典控制台不应出现原先的 `[K` 清行符字面文字；长任务中 Ctrl+C 仍可结束手动运行。恢复原来的自动触发状态：

```powershell
if (!$wasEnabled) { Disable-ScheduledTask -TaskName $taskName | Out-Null }
```

## 6. 原生自动测试

测试包附带编译好的 `winbackground.test.exe`，不需要安装 Go。它只使用临时目录和合成子进程，不注册任务或读取真实凭证：

```powershell
# 显式传入字符串参数，避免 Windows PowerShell 将带点号的测试开关拆开。
& (Join-Path $testDir 'winbackground.test.exe') '-test.v=true' '-test.timeout=90s'
if ($LASTEXITCODE -ne 0) { throw 'Windows 原生启动器测试未通过，请回传输出' }
```

必须看到最终 `PASS`。核心项 `TestRunForwardsExitCodeAndCapturesStreams`、`TestRunForwardsTransientExitCode`、`TestRunRotatesLogsWhileCollectorRuns`、`TestRunConvergesGrandchildrenHoldingThePipe`、`TestJobTerminatesChildrenWhenHandleCloses`、`TestRunStopsWhenLogStreamFails` 均必须 PASS；非 Windows 专用的 stub 测试、以及缺少符号链接权限时的 symlink 测试可以 SKIP。

开发机器有 Go 1.24+ / 仓库时，还可以在仓库根目录执行下面的真实调度门禁。只会创建随机临时任务和隔离探针，不修改生产 task：

```powershell
go test ./internal/winbackground -count=1
$env:TOKTRAIL_WINDOWS_SCHEDULER_E2E = '1'
go test ./internal/scheduler -run '^TestWindowsSchedulerNativeIntegration$' -count=1 -v
Remove-Item Env:TOKTRAIL_WINDOWS_SCHEDULER_E2E
$env:TOKTRAIL_WINDOWS_CONNECT_E2E = '1'
go test ./cmd/toktrail -run '^TestWindowsConnectNativeIntegration$' -count=1 -v
Remove-Item Env:TOKTRAIL_WINDOWS_CONNECT_E2E
```

必须实际 PASS，不能用 SKIP 代替。scheduler 原生测试会真实触发任务，检查没有控制台、两个日志和退出码 7；connect 原生测试还检查 refresh 幂等且 grants 不变。

## 7. 回滚到测试前的安装

等待当前任务结束后，禁用测试任务并恢复备份文件和 XML：

```powershell
Disable-ScheduledTask -TaskName $taskName | Out-Null
Copy-Item -LiteralPath (Join-Path $backup 'toktrail.exe') -Destination $exe -Force
if (Test-Path -LiteralPath (Join-Path $backup 'toktrail-background.exe')) {
  Copy-Item -LiteralPath (Join-Path $backup 'toktrail-background.exe') -Destination $oldHelper -Force
}
& schtasks.exe /Create /F /TN $taskName /XML (Join-Path $backup 'task-before.xml')
if ($LASTEXITCODE -ne 0) { throw '原任务 XML 恢复失败，请保留备份排查' }
```

没有旧 helper 备份时，新 helper 可以暂时留在安装目录；旧任务恢复后不会引用它。不要删除 device.json、grants.json、outbox 或扫描进度来回滚。

## 8. 回传结果

请回传：Windows/PowerShell 版本、隔离探针的 ExitCode 与 consoleHandle、强制关闭后子进程是否仍在、refresh 输出、任务的 Action/Principal/Interval、LastTaskResult、日志末尾的安全状态行。不要上传 device.json 正文、凭证或连接 ticket。
