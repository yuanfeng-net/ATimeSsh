# ATimeSsh 实施方案

## 1. 项目目标

ATimeSsh 是一个跨平台 SSH 管理面板。程序启动后自动选择本机可用端口并启动本地 Web 服务，然后自动打开浏览器进入管理界面。

核心能力：

- 首次启动设置安全密码，之后每次进入管理后台都必须验证安全密码。
- 管理服务器列表，可搜索和添加服务器。
- 添加服务器时配置名称、IP/域名、SSH 端口、账号和密码。
- 选中服务器后展示服务器信息，但不展示账号和密码。
- 为选中的服务器生成临时 SSH 访问链接。
- 展示临时链接及剩余有效时间，支持复制、续期和关闭。
- 支持 Windows、macOS、Linux，发布版本不依赖用户安装 Node.js、SQLite、OpenSSH 或 OpenSSL。

## 2. 总体架构

```text
ATimeSsh 可执行文件
├─ Rust/Tokio/Axum 本地 HTTP 服务
├─ SQLite 数据库
├─ Argon2id 密码哈希
├─ AES-256-GCM 凭据加密
├─ russh SSH 连接与 Relay
├─ React + TypeScript + Vite 管理后台
├─ CSS 样式系统
├─ SSH URI / 外部终端 Relay
└─ rust-embed 嵌入前端静态资源
```

### 2.1 技术选型

| 层次 | 技术 | 用途 |
| --- | --- | --- |
| 服务端 | Rust、Tokio、Axum | 异步服务和 HTTP API |
| SSH | `russh` | 跨平台 SSH 客户端和临时 Relay |
| 数据库 | SQLite、`rusqlite` `bundled` | 本地配置和服务器数据 |
| 密码 | `argon2` | 安全密码哈希 |
| 加密 | `aes-gcm`、`rand` | 加密保存 SSH 密码 |
| 路径 | `directories` | 获取各平台应用数据目录 |
| 浏览器 | `webbrowser` | 跨平台自动打开浏览器 |
| 前端 | React、TypeScript、Vite | 管理后台 |
| 样式 | CSS | 布局、响应式和主题 |
| 状态 | React state | 登录、服务器和会话状态 |
| 图标 | `lucide-react` | 操作栏和状态图标 |
| 静态资源 | `rust-embed` | 将 React 构建结果嵌入 Rust 二进制 |

## 3. 启动和认证流程

### 3.4 当前实现状态

以下能力已在 `native-host` 和 React 管理后台中实现：

- SQLite 数据库位于各平台用户数据目录的 `ATimeSsh/atimesh.sqlite3`，启动时自动创建表结构。
- 首次启动通过 `/api/auth/status` 判断是否需要设置安全密码；设置和登录接口使用 Argon2id 哈希。
- 登录成功后签发 `HttpOnly`、`SameSite=Strict` Cookie；服务器写入、临时会话生成、续期、撤销接口均要求有效登录会话。
- 由安全密码和独立盐值派生 AES-256-GCM 密钥，服务器 SSH 密码以密文和随机 nonce 写入 SQLite，前端不接收账号密码。
- 前端提供首启设置、登录锁屏、锁定按钮，并保留中英文切换和深浅色模式。
- 管理端口和每个活动服务器会话的 Relay 端口仍由操作系统随机分配，旧会话撤销时释放端口。
- SSH 目标连接优先枚举并绑定物理网卡地址，排除常见 TUN、VPN、WSL、Docker、Clash、Meta TUN 等虚拟接口；手动选择时 Windows/Linux/macOS 均绑定指定接口，接口不可用则失败，不静默回退到默认路由。
- 管理后台设置页支持网络出口选择：默认自动选择，亦可从已枚举的物理网卡中手动指定；偏好写入 SQLite `app_config.network_interface_index`，只影响后续主机指纹扫描和新建 Relay，当前会话不会被中断。`GET /api/network/interfaces`、`GET/POST /api/settings/network` 均要求已认证 Cookie。
- 服务器列表已增加受保护的 `GET /api/servers`，登录后从 SQLite 加载脱敏节点信息；新增节点会保存名称、地址和加密凭据，空数据库显示空列表。

当前验证要求：Relay 请求回执、EOF/exit-status 顺序、PTY、多 channel 和会话撤销必须通过自动化测试；生产前端不包含 mock 节点或 mock 会话。

目标服务器主机指纹已合并到服务器保存流程：保存前自动完成 SSH 握手、读取目标 SSH 公钥的 SHA-256 指纹并验证提交的账号密码，成功后写入 `servers.host_key`；握手、认证或指纹读取失败时保存请求直接失败，不会写入未验证的服务器。已有服务器再次保存时如果指纹变化也会拒绝覆盖；Relay 后续连接时指纹不匹配会拒绝连接。

### 3.1 启动流程

1. 使用 `directories::ProjectDirs` 创建应用数据目录。
2. 初始化 SQLite 数据库和迁移。
3. 检查是否已存在安全密码配置。
4. 监听 `127.0.0.1:0`，由操作系统分配可用端口。
5. 读取实际监听端口。
6. 启动 Axum 路由和静态资源服务。
7. 自动打开 `http://127.0.0.1:<port>`。
8. 进程退出时撤销所有临时 SSH 会话并关闭数据库连接。

默认只监听本机回环地址，避免管理面板暴露到局域网。后续如需远程访问，应单独增加显式配置和额外认证。

### 3.2 首次启动

```text
设置安全密码
确认安全密码
```

服务端校验两次输入一致后使用 Argon2id 生成密码哈希和盐值。前端不保存安全密码。

### 3.3 后续进入

```text
输入安全密码
```

验证成功后签发 HttpOnly、SameSite Cookie 会话。未登录请求不能访问服务器列表、服务器详情或 SSH 会话接口。

安全要求：

- 不保存明文安全密码。
- 登录失败使用指数退避限速，连续失败最长锁定 60 秒。
- Cookie 设置 `HttpOnly`、`SameSite=Strict`，本地服务可启用 `Secure`。
- 会话具有过期时间，锁定后台时服务端主动撤销全部 Relay。
- 忘记安全密码时只能清空本地数据并重新初始化。

## 4. 本地数据和加密

### 4.1 跨平台数据目录

```text
Windows: %USERPROFILE%\\ATimeSsh
macOS:   ~/Library/Application Support/ATimeSsh
Linux:   $XDG_DATA_HOME/ATimeSsh，未设置时为 ~/.local/share/ATimeSsh
```

程序不直接拼接盘符或平台路径分隔符，统一使用 `directories` 和 `std::path::PathBuf`。

### 4.2 数据库表

```sql
CREATE TABLE app_config (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  password_hash TEXT NOT NULL,
  password_salt BLOB NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE servers (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER NOT NULL DEFAULT 22,
  username TEXT NOT NULL,
  password_ciphertext BLOB NOT NULL,
  password_nonce BLOB NOT NULL,
  host_key TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE ssh_sessions (
  id INTEGER PRIMARY KEY,
  server_id INTEGER NOT NULL,
  token_hash BLOB NOT NULL,
  expires_at TEXT NOT NULL,
  max_expires_at TEXT NOT NULL,
  revoked_at TEXT,
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
);
```

服务器密码使用由安全密码派生的密钥进行 AES-256-GCM 加密。临时链接只在数据库中保存 Token 哈希，不保存可直接使用的完整 Token。

## 5. 管理后台设计

### 5.1 页面和布局

```text
┌────────────────────────────────────────────────────┐
│ ATimeSsh       搜索服务器       添加服务器    退出 │
├──────────────────┬─────────────────────────────────┤
│ 服务器列表        │ 服务器详情                       │
│                  │ 名称、地址、端口、状态             │
│ 生产服务器        │                                 │
│ 测试服务器        │ [生成临时 SSH 链接]               │
│                  │                                 │
│                  │ 临时链接、剩余时间                 │
│                  │ [复制] [续期] [关闭]                │
└──────────────────┴─────────────────────────────────┘
```

技术约定：

- 单页 React 组件管理初始化、登录和后台视图。
- React state 管理认证状态、服务器选中状态和临时会话状态。
- 使用 `fetch` 调用 Rust API。
- 使用组件内条件渲染实现添加服务器弹窗。
- 使用 Clipboard API 复制链接。
- 外部终端或 AI Agent 通过临时 SSH URI 连接 Relay。
- 使用 `lucide-react` 图标表达添加、搜索、复制、续期、关闭和退出等操作。
- 服务器密码和账号不返回给前端详情接口。

### 5.2 前端目录

```text
frontend/
├─ package.json
├─ vite.config.ts
├─ tsconfig.json
├─ src/
│  ├─ main.tsx
│  ├─ App.tsx
│  ├─ api/
│  │  ├─ client.ts
│  │  ├─ auth.ts
│  │  ├─ servers.ts
│  │  └─ sshSessions.ts
│  ├─ stores/
│  │  ├─ authStore.ts
│  │  └─ serverStore.ts
│  ├─ layouts/AdminLayout.tsx
│  ├─ pages/
│  │  ├─ SetupPage.tsx
│  │  ├─ LoginPage.tsx
│  │  └─ DashboardPage.tsx
│  ├─ components/
│  │  ├─ ServerSidebar.tsx
│  │  ├─ ServerDetail.tsx
│  │  ├─ AddServerDialog.tsx
│  │  ├─ SshSessionPanel.tsx
│  │  └─ Countdown.tsx
│  └─ styles/index.css
└─ dist/
```

### 5.3 添加服务器弹窗

表单字段：

- 服务器名称
- 服务器 IP 或域名
- SSH 端口，默认 `22`
- SSH 用户名
- SSH 密码

校验规则：必填校验、端口范围 `1-65535`、名称重复校验、IP/域名格式校验，以及服务器端的二次校验。

服务器详情只展示名称、IP/域名、SSH 端口、连接状态和最近连接时间，不展示用户名和密码。

## 6. 临时 SSH 链接

### 6.1 推荐实现

临时链接实现为“Token 鉴权的 SSH Relay”，而不是把密码放进普通 `ssh://` URL：

1. 用户选中服务器并点击生成。
2. 服务端生成高强度随机 Token，仅保存 Token 哈希。
3. 创建有效期，例如 10 分钟，并设置最大有效期上限。
4. Relay 使用本地加密凭据连接目标服务器。
5. 客户端通过临时 Token 连接 Relay。
6. Relay 验证 Token 后转发 SSH 通道。
7. 关闭操作立即撤销 Token 和对应通道。
8. 续期只能延长到 `max_expires_at` 以内。

第一阶段优先提供浏览器 Web Terminal；第二阶段提供 `atimesh connect` CLI，以便使用标准 OpenSSH 客户端体验。

### 6.2 展示内容

```text
临时 SSH 链接
ssh ...
剩余 09:58

[复制] [续期] [关闭]
```

倒计时以服务端 `expires_at` 为准，前端只负责展示并定期刷新状态，不能把本地递减计时作为最终权限判断。

示例接口响应：

```json
{
  "token": "one-time-display-token",
  "connect_command": "atimesh connect --token one-time-display-token --port <relay_port>",
  "expires_at": "2026-09-17T12:10:00Z",
  "max_expires_at": "2026-09-17T13:00:00Z",
  "status": "active"
}
```

完整 Token 只在生成接口响应中返回，后续查询接口返回脱敏链接或状态信息。

### 6.3 AI agent 完整连接 URI

为了让“复制”结果可以直接交给支持 SSH URI 或结构化连接参数的 AI agent，生成接口同时返回：

```text
ssh://<saved-ssh-username>:<temporary-token>@127.0.0.1:<relay-port>
```

复制按钮复制完整 `ssh://` URI，而不是只复制不含密码的 SSH 命令。URI 中的用户名使用添加服务器时保存的 SSH 用户名，例如 `root`；密码位置是本次会话的临时 Token，不是目标服务器密码。Token 仍只在生成响应和前端当前会话内明文存在，数据库只保存哈希。AI agent 解析 URI 后应使用保存的 SSH 用户名、`127.0.0.1`、随机端口和 Token 建立密码认证连接。原始 `connect_command` 继续返回，用于人工终端执行并在密码提示处粘贴 Token。

Relay 不引入额外的 `relay` 权限用户：每个临时端口只接受对应目标服务器保存的用户名和该会话 Token，之后宿主仍使用保存的真实 SSH 用户名和加密密码连接目标服务器。

该 URI 等同于临时访问凭据，复制、发送和日志记录都应按敏感信息处理；会话撤销或过期后 URI 立即失效。

## 7. Rust API

```text
POST   /api/auth/setup
POST   /api/auth/login
POST   /api/auth/logout
GET    /api/auth/status

GET    /api/servers
POST   /api/servers
POST   /api/servers/:id             # 注册/更新宿主侧目标连接配置
GET    /api/servers/:id
PATCH  /api/servers/:id
DELETE /api/servers/:id

POST   /api/servers/:id/ssh-sessions
GET    /api/ssh-sessions/:id/status
POST   /api/ssh-sessions/:id/renew
POST   /api/ssh-sessions/:id/revoke
WS     /api/ssh-sessions/:id/terminal

GET    /api/health
```

接口约定：

- 所有管理接口要求已认证 Cookie。
- `GET /api/servers` 和详情接口不返回账号、密码密文或解密后的密码。
- 删除服务器时级联撤销其临时会话。
- 会话到期、撤销或进程重启后不能继续建立连接。
- 统一返回结构化错误码，前端据此展示错误信息。

## 8. 跨平台发布

推荐发布目标：

```text
Windows x86_64: x86_64-pc-windows-msvc
Windows ARM64:  aarch64-pc-windows-msvc
macOS Intel:    x86_64-apple-darwin
macOS Apple Silicon: aarch64-apple-darwin
Linux x86_64:   x86_64-unknown-linux-gnu
Linux ARM64:    aarch64-unknown-linux-gnu
```

使用 GitHub Actions 和 `cargo-dist` 构建发布包，例如：

```text
ATimeSsh-windows-x86_64.exe
ATimeSsh-macos-x86_64
ATimeSsh-macos-aarch64
ATimeSsh-linux-x86_64
ATimeSsh-linux-aarch64
```

构建流程：

```text
npm ci
npm run build
cargo build --release
```

Rust 通过 `rust-embed` 提供 `frontend/dist`。生产包不携带 Node.js，Node.js 仅用于开发和构建阶段。

平台兼容要求：

- 浏览器启动统一使用 `webbrowser`。
- 信号处理同时覆盖 Windows Ctrl+C、macOS/Linux SIGINT 和 SIGTERM。
- SSH 主机指纹保存到 SQLite 的 `servers.host_key`，不依赖系统 OpenSSH 配置。
- 所有文件操作使用 Rust 跨平台路径 API。
- Linux/macOS 数据目录限制为当前用户可读写；Windows 使用用户主目录下的 `ATimeSsh`，更新或重装程序不会删除数据库。

## 9. 项目结构

```text
atimesh/
├─ Cargo.toml
├─ src/
│  ├─ main.rs
│  ├─ config.rs
│  ├─ db.rs
│  ├─ auth/
│  ├─ crypto/
│  ├─ servers/
│  ├─ ssh/
│  ├─ sessions/
│  └─ web/
├─ frontend/
├─ migrations/
├─ dist-workspace.toml
└─ README.md
```

## 10. 分阶段实施

### 阶段一：MVP

- Rust 项目和 React 项目初始化。
- 动态端口监听和自动打开浏览器。
- SQLite 初始化和迁移。
- 首次设置安全密码、登录、退出。
- 服务器添加、编辑、删除、搜索和详情展示。
- SSH 密码加密保存，前端不返回敏感字段。

### 阶段二：临时会话

- `russh` 连接目标服务器。
- Token 生成、哈希存储和过期校验。
- SSH Relay 的真实端到端测试和协议顺序回归测试。
- 倒计时、复制、续期和关闭。
- 会话断开、到期和程序退出清理。

### 阶段三：标准 SSH 客户端

- 开发 `atimesh connect` CLI。
- 增加 SSH Relay 监听和 Token 鉴权。
- 支持多会话隔离和并发连接。
- 完善主机指纹确认和审计日志。

### 阶段四：发布和质量

- 六类目标平台构建。
- 自动化单元测试、API 测试和跨平台构建测试。
- 日志脱敏、数据库备份和数据迁移。
- 版本升级、回滚和安装包/绿色版发布。

## 11. 验收标准

- Windows、macOS、Linux 均能启动并自动选择可用端口。
- 启动后自动打开浏览器并访问正确地址。
- 首次启动必须设置安全密码，后续进入必须验证。
- 服务器密码只以密文保存，不出现在前端响应和日志中。
- 服务器列表支持搜索、添加、编辑、删除和选中查看。
- 详情页不展示账号密码。
- 临时 Token 不可预测，生成后能复制并显示剩余时间。
- 到期或关闭后链接立即失效。
- 续期不能超过最大有效期。
- 程序重启后原有临时会话默认全部失效。
- SSH 主机指纹异常时明确提示。
- 发布包不依赖 Node.js、SQLite、OpenSSH 或 OpenSSL。

## 12. 默认决策

- 默认监听地址：`127.0.0.1`。
- 默认 SSH 端口：`22`。
- 临时链接默认有效期：`10` 分钟。
- 临时链接续期必须受最大有效期限制。
- 第一版优先实现浏览器 Web Terminal，CLI Relay 作为第二阶段能力。
- 前端只展示服务端返回的服务器信息和会话状态，不在客户端重新计算候选资格、权限或会话有效性。

## 13. 系统托盘和端口生命周期

### 13.1 系统托盘

正式发布的 Rust 宿主进程必须创建系统托盘图标，覆盖 Windows 任务栏通知区域、macOS 菜单栏和 Linux system tray（具体可用性取决于桌面环境）。托盘菜单固定包含：

- `打开管理后台 / Open dashboard`：读取当前 Web 服务地址并重新打开浏览器。
- `退出 / Exit`：先撤销所有临时 SSH 会话、释放 Relay 端口，再停止 HTTP 服务并退出进程。

托盘图标应由 `tray-icon` 创建，不能通过前端页面模拟。关闭浏览器窗口不应退出宿主进程，用户可从托盘重新打开管理后台。

### 13.2 管理后台端口

启动时由 Rust 宿主执行：

```rust
let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
let web_port = listener.local_addr()?.port();
```

必须持有该 `TcpListener` 直到 HTTP 服务退出，不能先探测端口再释放后重新监听，否则会产生端口竞争窗口。实际地址通过 `/api/runtime` 返回给前端，浏览器打开的地址为：

```text
http://127.0.0.1:<web_port>/
```

### 13.3 临时 SSH Relay 端口

每个服务器的每条活动临时会话都由宿主单独申请一个端口：

```rust
let relay_listener = TcpListener::bind(("127.0.0.1", 0)).await?;
let relay_port = relay_listener.local_addr()?.port();
```

端口分配规则：

- 不写死端口号，不使用固定的 `51842`。
- 每次生成临时 SSH 链接都重新申请端口。
- 一个服务器再次生成链接时，先撤销旧会话并释放旧端口。
- 不同服务器的活动会话不能共享端口。
- Relay `TcpListener` 必须保存在会话租约中，直到会话到期、撤销或程序退出。
- 端口分配和会话表更新必须在同一服务端流程内完成，避免“显示了端口但实际未占用”的竞态。
- 前端展示服务端返回的 `port` 和 `connect_command`，不自行决定权限端口。

建议会话对象包含：

```text
session_id
server_id
relay_port
token_hash
expires_at
max_expires_at
listener_handle
revoked_at
```

宿主层已经提供 `native-host/`：Web 服务使用操作系统随机端口，临时会话持有独立端口租约，并包含系统托盘菜单。Relay 使用 `russh` 启动真正的 SSH 服务端并用临时 Token 做密码认证；服务器注册 API 将目标 SSH 配置绑定到 `server_id`，认证成功后由 `russh` client 连接目标主机，并通过双向 channel 转发 PTY 数据。`ServerConfig.password` 运行时只存在于宿主内存，持久化数据使用安全密码派生密钥加密，并校验目标主机指纹。

Relay 对客户端的 `pty-request` 和 `shell-request` 会显式返回 SSH channel success，避免 OpenSSH 在临时 Token 认证成功后因终端协商未完成而立即断开。

## 14. Windows 无控制台窗口

Windows Release 宿主在 `native-host/src/main.rs` 顶部声明 `windows_subsystem = "windows"`，因此启动时不会创建黑色命令行窗口；托盘图标、浏览器自动打开、随机本地端口和 HTTP 服务仍由同一个 GUI subsystem 进程提供。该属性仅对 Windows 生效，macOS/Linux 保持原有跨平台构建行为。
