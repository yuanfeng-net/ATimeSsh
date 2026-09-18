# ATimeSsh

中文 | [English](README.en.md)

ATimeSsh 是一个跨平台、本地优先的 SSH 管理面板。它使用 Rust 提供本地服务和 SSH Relay，使用 React + TypeScript 提供管理后台；程序启动后会自动选择一个可用的本机端口并打开浏览器。

## 功能

- 首次启动设置安全密码，后续进入管理后台需要验证。
- 服务器列表、搜索和添加服务器。添加时自动连接目标 SSH 服务并保存主机指纹。
- 服务器账号和密码只在本地加密保存，详情页不展示凭据。
- 为服务器生成完整的临时 SSH URI：`ssh://用户名:Token@127.0.0.1:随机端口`。
- 临时 Relay 默认有效 10 分钟，支持复制、续期和立即关闭；每台服务器使用独立随机端口。
- Relay 使用保存的服务器用户名，不引入额外的固定用户。
- Windows、macOS、Linux 支持；桌面启动时所有平台都不会额外弹出命令行窗口。Windows 使用 GUI 子系统；macOS 使用 `.app` 启动；Linux 使用 `Terminal=false` 的 `.desktop` 启动器。
- 系统托盘菜单可以重新打开管理后台或退出程序。
- 中英文国际化、深色/浅色模式和微软雅黑字体。
- 设置页支持网络出口“自动选择”或手动指定物理网卡；会避开常见 TUN、VPN、WSL、Docker 和虚拟接口。

## 技术架构

```text
ATimeSsh
├─ frontend/                  React + TypeScript + Vite 管理后台
├─ native-host/               Rust + Tokio + Axum 本地服务
│  ├─ russh                   SSH 主机指纹扫描与临时 Relay
│  ├─ rusqlite (bundled)      本地 SQLite 数据库
│  ├─ Argon2                  安全密码哈希
│  ├─ AES-256-GCM             服务器密码加密
│  └─ rust-embed              将 frontend/dist 嵌入可执行文件
└─ ui-mockups/                管理后台 UI 设计稿
```

管理服务默认只监听 `127.0.0.1`，不会主动暴露到局域网。管理端口和临时 Relay 端口均由操作系统从可用端口中随机分配。

## 环境要求

- Rust stable（包含 Cargo）
- Node.js 18+ 与 npm
- Windows 开发时建议使用支持 C/C++ 构建工具的 Rust 工具链
- macOS/Linux 需要可用的桌面环境才能自动打开浏览器和显示托盘图标

## 快速开始

### 1. 构建前端

```powershell
cd frontend
npm install
npm run build
```

`npm run build` 会执行 TypeScript 检查并生成 `frontend/dist`。Rust 的 `rust-embed` 会从该目录读取管理后台资源，因此每次前端改动后都需要重新构建 Rust 宿主。

### 2. 运行开发版宿主

```powershell
cd native-host
cargo run
```

启动后程序会：

1. 初始化本地 SQLite 数据库。
2. 监听 `127.0.0.1:0`，由操作系统分配管理端口。
3. 启动托盘图标。
4. 自动打开管理后台。
5. 首次启动进入安全密码设置页。

### 3. 构建 Release

```powershell
cd frontend
npm run build
cd ..\native-host
cargo build --release
```

可执行文件位于：

```text
native-host/target/release/atimesh-host.exe   # Windows
native-host/target/release/atimesh-host       # macOS/Linux
```

桌面发布时请使用平台原生启动器，确保所有平台都不会额外出现命令行窗口：

- Windows：Release 可执行文件已使用 GUI 子系统，直接启动 `atimesh-host.exe`。
- macOS：创建 `ATimeSsh.app/Contents/MacOS/`，将 Release 二进制复制为 `ATimeSsh.app/Contents/MacOS/atimesh-host`，并将 [`packaging/macos/Info.plist`](packaging/macos/Info.plist) 复制到 `ATimeSsh.app/Contents/Info.plist`。
- Linux：确保 `atimesh-host` 已安装到 `PATH`，再将 [`packaging/linux/atimesh.desktop`](packaging/linux/atimesh.desktop) 安装到 `~/.local/share/applications/`；该启动器明确设置了 `Terminal=false`。AppImage 也应使用同一桌面入口设置。

macOS 打包示例：

```bash
mkdir -p ATimeSsh.app/Contents/MacOS
cp native-host/target/release/atimesh-host ATimeSsh.app/Contents/MacOS/atimesh-host
cp packaging/macos/Info.plist ATimeSsh.app/Contents/Info.plist
chmod +x ATimeSsh.app/Contents/MacOS/atimesh-host
open ATimeSsh.app
```

Linux 桌面安装示例：

```bash
install -Dm755 native-host/target/release/atimesh-host "$HOME/.local/bin/atimesh-host"
install -Dm644 packaging/linux/atimesh.desktop "$HOME/.local/share/applications/atimesh.desktop"
```

如果发行版不自动刷新应用菜单，可执行 `update-desktop-database "$HOME/.local/share/applications"`。

不要从已经打开的终端执行程序，否则程序会继承当前终端，这是操作系统的正常行为。程序不会主动创建命令行窗口；运行时错误日志写入用户数据目录下的 `ATimeSsh/atimesh.log`，不会输出到 stdout/stderr。

## 使用流程

1. 启动 ATimeSsh，首次设置至少 8 位安全密码。
2. 点击“添加节点”，输入名称、主机/IP、SSH 端口、用户名和密码。
3. 保存时程序会通过 SSH 握手读取目标主机公钥指纹，并验证账号密码；失败时不会保存服务器。
4. 选中服务器后点击“生成临时链接”。
5. 复制完整 `ssh://` URI，交给支持 SSH URI 的终端或 AI Agent。
6. 到期前可以续期；不再使用时点击关闭，立即释放 Relay 端口。

临时链接中的 Token 是 Relay 登录凭据，不是目标服务器密码。数据库只保存 Token 的 SHA-256 哈希；Token 明文只在生成响应和当前前端会话中短暂存在。

## 网络出口设置

进入左侧栏底部的“设置”：

- **自动选择**：优先使用可用物理网卡，避开常见 TUN、VPN、WSL、Docker、Clash、Meta TUN 等接口。
- **手动选择**：从枚举到的物理接口中指定一个网卡。
- 选择会保存到 SQLite 的 `app_config` 表。
- 设置只影响后续主机指纹扫描和新建 Relay，不会强制中断已有会话。
- Windows 连接会使用接口索引设置 `IP_UNICAST_IF` / `IPV6_UNICAST_IF`；指定接口不可用时仍保留默认路由回退。

## 数据与安全

应用数据目录由系统用户数据目录决定：

| 平台 | 默认目录 |
| --- | --- |
| Windows | `%LOCALAPPDATA%\ATimeSsh`（部分环境使用 `%APPDATA%`） |
| macOS | `~/Library/Application Support/ATimeSsh` |
| Linux | `$XDG_DATA_HOME/ATimeSsh`，未设置时为 `~/.local/share/ATimeSsh` |

运行日志文件为上述目录中的 `atimesh.log`。桌面启动不会创建额外命令行窗口。

主要文件是 `atimesh.sqlite3`。数据库包含服务器配置、加密密码、主机指纹、应用设置和临时会话元数据。

- 安全密码：Argon2 哈希，不保存明文。
- 服务器密码：由安全密码派生的 AES-256-GCM 密钥加密。
- 临时 Token：只保存 SHA-256 哈希。
- 主机指纹：首次保存时扫描；已有服务器指纹变化时拒绝覆盖。
- 管理接口：除运行时信息和认证状态外均要求已认证的 HttpOnly、SameSite Cookie。

不要把 SQLite 文件、临时链接 Token 或安全密码提交到 Git，也不要把完整临时链接粘贴到公开日志。

## 常用 API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/api/auth/status` | 查询是否已配置/已认证 |
| `POST` | `/api/auth/setup` | 首次设置安全密码 |
| `POST` | `/api/auth/login` | 登录管理后台 |
| `GET` | `/api/servers` | 获取脱敏服务器列表 |
| `POST` | `/api/servers/{id}` | 验证并保存服务器 |
| `POST` | `/api/servers/{id}/ssh-sessions` | 创建临时 Relay |
| `POST` | `/api/ssh-sessions/{id}/renew` | 续期 Relay |
| `POST` | `/api/ssh-sessions/{id}` | 关闭 Relay |
| `GET` | `/api/network/interfaces` | 获取网卡列表 |
| `GET/POST` | `/api/settings/network` | 读取/保存网卡偏好 |

除 `/api/runtime`、`/api/auth/status` 外，接口均要求登录 Cookie。

## 故障排查

### 添加服务器失败

确认目标地址、SSH 端口、用户名和密码正确，并确认目标服务器允许密码认证。保存操作必须完成 SSH 握手、主机指纹读取和账号验证。

### SSH 握手被 TUN/VPN 接管

进入“设置”手动选择实际物理网卡后，再重新保存服务器或生成新的临时链接。已有 Relay 不会自动切换网卡。

### 临时链接立即断开

检查链接是否已超过 10 分钟有效期、是否达到续期上限，或是否已在管理后台点击关闭。重新生成链接会撤销该服务器之前的活动 Relay。

### 端口冲突

管理端口和 Relay 端口均使用操作系统绑定 `:0` 分配；如果外部安全软件阻止本地监听，请允许 ATimeSsh 访问回环地址 `127.0.0.1`。

## 开发检查

```powershell
cd native-host
cargo fmt -- --check
cargo check
cd ..\frontend
npm run build
```

## 许可

详见 [LICENSE](LICENSE)。
