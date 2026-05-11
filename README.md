# WinPortProxyWeb

一个用于管理 Windows `netsh interface portproxy` 的本地 Web 面板，并支持 WSL2 端口一键转发。

## 功能

- 查看 Windows `v4tov4` 端口转发规则
- 新增和删除 `netsh interface portproxy` 规则
- 列出 WSL 发行版并自动获取 WSL IPv4
- 一键创建 `0.0.0.0:<Windows端口> -> <WSL IP>:<WSL服务端口>` 转发
- 手动点击后创建 Windows 防火墙入站 TCP 放行规则
- 默认管理页面只监听 `127.0.0.1:5179`

## 运行

开发运行需要安装 .NET SDK：

```bash
dotnet run
```

然后打开：

```text
http://127.0.0.1:5179
```

新增/删除端口转发规则和创建防火墙规则通常需要管理员权限。建议用管理员终端运行程序。

## 发布为无需安装 .NET 的单文件 exe

在装有 .NET SDK 的机器上执行：

```bash
dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true
```

输出目录通常是：

```text
bin/Release/net8.0/win-x64/publish/
```

把里面的 `WinPortProxyWeb.exe` 发给用户即可，目标 Windows 机器不需要单独安装 .NET。

## 注意事项

- `portproxy` 只处理 TCP，不处理 UDP。
- WSL2 的 IP 可能在 WSL 重启后变化，变化后需要重新应用 WSL 转发规则。
- `0.0.0.0` 会让 Windows 在所有网卡上监听该端口，局域网设备可能可以访问。
- 本工具不会自动开放防火墙；只有点击页面中的防火墙放行按钮时才会创建规则。
- 如果需要远程访问管理页面，请先自行加入认证和 HTTPS，不建议直接暴露本管理面板。
