# ATimeSsh

[中文](README.md) | English

ATimeSsh is a cross-platform, local-first SSH management panel. Rust provides the local service and SSH Relay, while React + TypeScript provides the administration UI. On startup, the application selects an available local port and opens the browser.

## Features

- Set a security password on first launch and verify it whenever the dashboard is opened.
- Search and manage a server list. Saving a server automatically connects to the target SSH service and records its host fingerprint.
- Store server usernames and passwords encrypted locally; credentials are never shown in server details.
- Generate a complete temporary SSH URI: `ssh://username:Token@127.0.0.1:random-port`.
- Temporary Relays are valid for 10 minutes by default and support copy, renewal, and immediate revocation. Each server receives its own random port.
- Relay authentication uses the saved server username and does not introduce a fixed extra user.
- Support Windows, macOS, and Linux. Desktop launches do not open an additional command-line window on any platform. Windows uses the GUI subsystem, macOS uses an `.app`, and Linux uses a `.desktop` launcher with `Terminal=false`.
- A system tray menu can reopen the dashboard or exit the application.
- Chinese/English localization, dark/light themes, and Microsoft YaHei typography.
- The settings page supports automatic network selection or a manually selected physical adapter, while avoiding common TUN, VPN, WSL, Docker, and virtual interfaces.

## Architecture

```text
ATimeSsh
├─ frontend/                  React + TypeScript + Vite administration UI
├─ native-host/               Rust + Tokio + Axum local service
│  ├─ russh                   SSH host-key scanning and temporary Relay
│  ├─ rusqlite (bundled)      Local SQLite database
│  ├─ Argon2                  Security-password hashing
│  ├─ AES-256-GCM             Server-password encryption
│  └─ rust-embed              Embeds frontend/dist into the executable
└─ ui-mockups/                Administration UI mockups
```

The management service listens on `127.0.0.1` by default and does not expose itself to the LAN. Both the management port and temporary Relay ports are assigned randomly by the operating system.

## Requirements

- Rust stable with Cargo
- Node.js 18+ and npm
- On Windows, a Rust toolchain with the required C/C++ build tools is recommended
- On macOS/Linux, a desktop environment is required for automatic browser opening and the tray icon

## Quick Start

### 1. Build the frontend

```powershell
cd frontend
npm install
npm run build
```

`npm run build` runs the TypeScript check and generates `frontend/dist`. The Rust `rust-embed` integration reads the dashboard assets from this directory, so the Rust host must be rebuilt after frontend changes.

### 2. Run the development host

```powershell
cd native-host
cargo run
```

The application will:

1. Initialize the local SQLite database.
2. Listen on `127.0.0.1:0` and let the operating system assign the management port.
3. Start the system tray icon.
4. Open the dashboard automatically.
5. Show the security-password setup page on first launch.

### 3. Build a release binary

```powershell
cd frontend
npm install
npm run build
cd ..\native-host
cargo build --release
```

The binaries are generated at:

```text
native-host/target/release/atimesh-host.exe   # Windows
native-host/target/release/atimesh-host       # macOS/Linux
```

Use each platform's native desktop launcher so no platform opens an additional command-line window:

- Windows: the release executable already uses the GUI subsystem; launch `atimesh-host.exe` directly.
- macOS: create `ATimeSsh.app/Contents/MacOS/`, copy the release binary to `ATimeSsh.app/Contents/MacOS/atimesh-host`, and copy [`packaging/macos/Info.plist`](packaging/macos/Info.plist) to `ATimeSsh.app/Contents/Info.plist`.
- Linux: install `atimesh-host` on `PATH`, then install [`packaging/linux/atimesh.desktop`](packaging/linux/atimesh.desktop) into `~/.local/share/applications/`. The launcher explicitly sets `Terminal=false`. AppImage packaging should use the same desktop entry.

macOS packaging example:

```bash
mkdir -p ATimeSsh.app/Contents/MacOS
cp native-host/target/release/atimesh-host ATimeSsh.app/Contents/MacOS/atimesh-host
cp packaging/macos/Info.plist ATimeSsh.app/Contents/Info.plist
chmod +x ATimeSsh.app/Contents/MacOS/atimesh-host
open ATimeSsh.app
```

Linux desktop installation example:

```bash
install -Dm755 native-host/target/release/atimesh-host "$HOME/.local/bin/atimesh-host"
install -Dm644 packaging/linux/atimesh.desktop "$HOME/.local/share/applications/atimesh.desktop"
```

If the distribution does not refresh its application menu automatically, run `update-desktop-database "$HOME/.local/share/applications"`.

Do not launch from an already-open terminal if you want no terminal window; the process will otherwise inherit that terminal by normal OS behavior. ATimeSsh does not create a command-line window itself. Runtime errors are written to `ATimeSsh/atimesh.log` in the user-data directory instead of stdout/stderr.

## Usage Flow

1. Start ATimeSsh and set an 8-character-or-longer security password on first launch.
2. Click “Add Node” and enter the name, host/IP, SSH port, username, and password.
3. Saving performs an SSH handshake, reads the target host public-key fingerprint, and verifies the account. Failed verification does not save the server.
4. Select a server and click “Generate Temp Link”.
5. Copy the complete `ssh://` URI into a terminal or AI Agent that supports SSH URIs.
6. Renew the link before expiration, or revoke it immediately when no longer needed.

The Token in a temporary link is a Relay credential, not the target server password. Only a SHA-256 Token hash is stored in the database; the plaintext Token exists temporarily in the generation response and the current frontend session.

## Network Egress Settings

Open “Settings” at the bottom of the left sidebar:

- **Automatic selection**: prefer available physical adapters and avoid common TUN, VPN, WSL, Docker, Clash, Meta TUN, and other virtual interfaces.
- **Manual selection**: choose one of the detected physical adapters.
- The preference is stored in SQLite in the `app_config` table.
- The preference applies only to future host-key scans and new Relays; active sessions are not forcibly interrupted.
- On Windows, Linux, and macOS, manual selection binds connections to the selected physical adapter. If it is unavailable, the connection fails instead of silently falling back to the default route.

## Data and Security

Application data is stored under the platform user-data directory:

| Platform | Default directory |
| --- | --- |
| Windows | `%USERPROFILE%\ATimeSsh` (for example `C:\Users\username\ATimeSsh`) |
| macOS | `~/Library/Application Support/ATimeSsh` |
| Linux | `$XDG_DATA_HOME/ATimeSsh`, or `~/.local/share/ATimeSsh` when unset |

The main file is `atimesh.sqlite3`. It contains server configuration, encrypted passwords, host fingerprints, application settings, and temporary-session metadata.

The runtime log is `atimesh.log` in the same directory. Desktop launches do not create an additional command-line window.

On Windows, the first launch automatically migrates data from the legacy `%LOCALAPPDATA%\ATimeSsh` directory to `%USERPROFILE%\ATimeSsh`; subsequent updates or reinstalls do not remove this directory.

- Security password: Argon2 hash; plaintext is never stored.
- Server password: encrypted with AES-256-GCM using a key derived from the security password.
- Temporary Token: only its SHA-256 hash is stored.
- Host fingerprint: scanned during the first save; a changed fingerprint rejects updates to an existing server.
- Management API: all management endpoints require an authenticated HttpOnly, SameSite cookie, except runtime and authentication-status endpoints.

Do not commit the SQLite database, temporary-link Tokens, or security password to Git. Do not paste complete temporary links into public logs.

## Common API

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/auth/status` | Check configuration and authentication state |
| `POST` | `/api/auth/setup` | Set the first security password |
| `POST` | `/api/auth/login` | Log into the dashboard |
| `GET` | `/api/servers` | Get the redacted server list |
| `POST` | `/api/servers/{id}` | Verify and save a server |
| `POST` | `/api/servers/{id}/ssh-sessions` | Create a temporary Relay |
| `POST` | `/api/ssh-sessions/{id}/renew` | Renew a Relay |
| `POST` | `/api/ssh-sessions/{id}` | Revoke a Relay |
| `GET` | `/api/network/interfaces` | List network interfaces |
| `GET/POST` | `/api/settings/network` | Read or save the interface preference |

All endpoints except `/api/runtime` and `/api/auth/status` require the login cookie.

## Troubleshooting

### Server save failed

Verify the target address, SSH port, username, and password. The target must allow password authentication. Saving requires a successful SSH handshake, host-key read, and account verification.

### SSH handshake is routed through a TUN/VPN adapter

Open Settings, manually select the physical adapter, then save the server again or generate a new temporary link. Existing Relays do not switch adapters automatically.

### Temporary link disconnects immediately

Check whether the link has passed its 10-minute lifetime or renewal limit, or whether it was revoked in the dashboard. Generating a new link revokes the previous active Relay for that server.

### Port conflict

The management and Relay listeners use OS-assigned `:0` ports. If security software blocks local listeners, allow ATimeSsh to use the loopback address `127.0.0.1`.

## Development Checks

```powershell
cd native-host
cargo fmt -- --check
cargo check
cd ..\frontend
npm run build
```

## License

See [LICENSE](LICENSE).
