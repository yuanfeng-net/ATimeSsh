#![cfg_attr(windows, windows_subsystem = "windows")]

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use if_addrs::get_if_addrs;
use rand::RngExt;
use rusqlite::{params, Connection, OptionalExtension};
use russh::server::{self, Auth, Msg, Server as RusshServer, Session};
use russh::{
    client, Channel, ChannelId, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Preferred, Pty, Sig,
};
use rust_embed::RustEmbed;
use serde::Deserialize;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    io::Write,
    net::{IpAddr, SocketAddr},
    path::{Path as FsPath, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tokio::{
    net::{lookup_host, TcpListener, TcpSocket, TcpStream},
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem},
    Icon, TrayIconBuilder,
};
use uuid::Uuid;

const DEFAULT_HOST: &str = "127.0.0.1";
const SESSION_MAX_DURATION: Duration = Duration::from_secs(48 * 60 * 60);

fn log_message(message: impl AsRef<str>) {
    let dir = app_data_dir();
    if fs::create_dir_all(&dir).is_err() {
        return;
    }
    let _ = harden_path(&dir, 0o700);
    let path = dir.join("atimesh.log");
    let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };
    let _ = harden_path(&dir.join("atimesh.log"), 0o600);
    let _ = writeln!(
        file,
        "[{}] {}",
        epoch_seconds(SystemTime::now()),
        message.as_ref()
    );
}

#[derive(RustEmbed)]
#[folder = "../frontend/dist/"]
struct FrontendAssets;

#[derive(Clone)]
struct AppState {
    app_port: u16,
    leases: Arc<Mutex<HashMap<String, SessionLease>>>,
    servers: Arc<Mutex<HashMap<String, ServerConfig>>>,
    db: Arc<Mutex<Connection>>,
    auth_sessions: Arc<Mutex<HashMap<String, SystemTime>>>,
    encryption_key: Arc<Mutex<Option<[u8; 32]>>>,
    login_throttle: Arc<Mutex<LoginThrottle>>,
}

#[derive(Default)]
struct LoginThrottle {
    failures: u32,
    blocked_until: Option<SystemTime>,
}

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Deserialize)]
struct ServerConfig {
    name: String,
    host: String,
    port: u16,
    username: String,
    password: String,
    host_key: Option<String>,
}

#[derive(Serialize)]
struct ServerSummary {
    id: String,
    name: String,
    host: String,
    port: u16,
    environment: String,
    status: &'static str,
    latency: Option<u16>,
    last_seen: String,
    host_key: Option<String>,
}

#[derive(Serialize)]
struct ServerDetails {
    id: String,
    name: String,
    host: String,
    port: u16,
    username: String,
    environment: String,
    host_key: Option<String>,
}

#[derive(Deserialize)]
struct UpdateServerRequest {
    name: String,
    host: String,
    port: u16,
    username: String,
    #[serde(default)]
    password: String,
}

#[derive(Deserialize)]
struct AuthRequest {
    password: String,
}

#[derive(Serialize)]
struct AuthStatusResponse {
    configured: bool,
    authenticated: bool,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[allow(dead_code)]
struct SessionLease {
    server_id: String,
    token: String,
    port: u16,
    relay_task: JoinHandle<()>,
    expires_at: SystemTime,
    max_expires_at: SystemTime,
}

#[derive(Serialize)]
struct RuntimeResponse {
    app_port: u16,
    host: &'static str,
}

#[derive(Serialize)]
struct NetworkInterfaceSummary {
    index: Option<u32>,
    name: String,
    ip: String,
    is_tunnel: bool,
    selectable: bool,
}

#[derive(Deserialize)]
struct NetworkSettingsRequest {
    interface_index: Option<u32>,
}

#[derive(Serialize)]
struct NetworkSettingsResponse {
    interface_index: Option<u32>,
    mode: &'static str,
}

#[derive(Serialize)]
struct SessionResponse {
    session_id: String,
    server_id: String,
    port: u16,
    token: String,
    connect_command: String,
    connect_uri: String,
    expires_at: u64,
    max_expires_at: u64,
}

#[derive(Serialize)]
struct SessionStatusResponse {
    session_id: String,
    server_id: String,
    port: u16,
    expires_at: u64,
    max_expires_at: u64,
    status: &'static str,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = Arc::new(Mutex::new(init_database()?));
    let app_listener = TcpListener::bind((DEFAULT_HOST, 0)).await?;
    let app_port = app_listener.local_addr()?.port();
    let state = AppState {
        app_port,
        leases: Arc::new(Mutex::new(HashMap::new())),
        servers: Arc::new(Mutex::new(HashMap::new())),
        db,
        auth_sessions: Arc::new(Mutex::new(HashMap::new())),
        encryption_key: Arc::new(Mutex::new(None)),
        login_throttle: Arc::new(Mutex::new(LoginThrottle::default())),
    };
    let dashboard_url = format!("http://{DEFAULT_HOST}:{app_port}/");
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let api_state = state.clone();
    let expiry_leases = state.leases.clone();
    let expiry_db = state.db.clone();

    tokio::spawn(async move {
        expire_sessions(expiry_leases, expiry_db).await;
    });

    tokio::spawn(async move {
        let app = Router::new()
            .route("/api/runtime", get(runtime))
            .route("/api/auth/status", get(auth_status))
            .route("/api/auth/setup", post(auth_setup))
            .route("/api/auth/login", post(auth_login))
            .route("/api/auth/logout", post(auth_logout))
            .route("/api/network/interfaces", get(list_network_interfaces))
            .route(
                "/api/settings/network",
                get(get_network_settings).post(set_network_settings),
            )
            .route(
                "/api/servers/{server_id}/ssh-sessions",
                get(get_session).post(create_session),
            )
            .route("/api/servers", get(list_servers))
            .route(
                "/api/servers/{server_id}",
                get(get_server).post(upsert_server).put(update_server),
            )
            .route("/api/ssh-sessions/{session_id}", post(revoke_session))
            .route("/api/ssh-sessions/{session_id}/renew", post(renew_session))
            .route("/api/ssh-sessions/{session_id}/status", get(session_status))
            .fallback(static_asset)
            .layer(DefaultBodyLimit::max(64 * 1024))
            .with_state(api_state);
        let result = axum::serve(app_listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await;
        if let Err(error) = result {
            log_message(format!("ATimeSsh HTTP server stopped: {error}"));
        }
    });

    open_dashboard(&dashboard_url);
    run_tray(dashboard_url, shutdown_tx);
}

async fn runtime(State(state): State<AppState>) -> Json<RuntimeResponse> {
    Json(RuntimeResponse {
        app_port: state.app_port,
        host: DEFAULT_HOST,
    })
}

fn init_database() -> Result<Connection, rusqlite::Error> {
    let dir = app_data_dir();
    migrate_legacy_data_dir(&dir)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    fs::create_dir_all(&dir)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    harden_path(&dir, 0o700)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    let path = dir.join("atimesh.sqlite3");
    if !path.exists() {
        fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    }
    harden_path(&path, 0o600)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    let connection = Connection::open(path)?;
    connection.execute_batch("PRAGMA journal_mode = WAL;")?;
    let _ = harden_path(&dir.join("atimesh.sqlite3-wal"), 0o600);
    let _ = harden_path(&dir.join("atimesh.sqlite3-shm"), 0o600);
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS servers (
           id TEXT PRIMARY KEY, name TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL,
           username TEXT NOT NULL, password_ciphertext BLOB NOT NULL, password_nonce BLOB NOT NULL,
           host_key TEXT
         );",
    )?;
    let has_legacy_token = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('ssh_sessions') WHERE name = 'token')",
        [],
        |row| row.get::<_, i64>(0),
    )? == 1;
    if has_legacy_token {
        // Session leases are memory-only and are never restored after restart, so the
        // old plaintext-token table can be safely replaced during schema migration.
        connection.execute_batch("DROP TABLE ssh_sessions;")?;
    }
    let has_host_key = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('servers') WHERE name = 'host_key')",
        [],
        |row| row.get::<_, i64>(0),
    )? == 1;
    if !has_host_key {
        connection.execute_batch("ALTER TABLE servers ADD COLUMN host_key TEXT;")?;
    }
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS app_config (key TEXT PRIMARY KEY, value BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS servers (
           id TEXT PRIMARY KEY, name TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL,
           username TEXT NOT NULL, password_ciphertext BLOB NOT NULL, password_nonce BLOB NOT NULL,
           host_key TEXT
         );
         CREATE TABLE IF NOT EXISTS ssh_sessions (
           id TEXT PRIMARY KEY, server_id TEXT NOT NULL, port INTEGER NOT NULL, token_hash BLOB NOT NULL,
           expires_at INTEGER NOT NULL, max_expires_at INTEGER NOT NULL
         );
         DELETE FROM ssh_sessions;",
    )?;
    Ok(connection)
}

fn app_data_dir() -> PathBuf {
    #[cfg(windows)]
    if let Some(home) = dirs::home_dir() {
        return home.join("ATimeSsh");
    }

    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ATimeSsh")
}

#[cfg(windows)]
fn migrate_legacy_data_dir(target: &FsPath) -> std::io::Result<()> {
    let Some(data_local) = dirs::data_local_dir() else {
        return Ok(());
    };
    let legacy = data_local.join("ATimeSsh");
    if legacy == target || !legacy.exists() {
        return Ok(());
    }

    if !target.exists() {
        if fs::rename(&legacy, target).is_ok() {
            return Ok(());
        }
        fs::create_dir_all(target)?;
    }

    for entry in fs::read_dir(&legacy)? {
        let entry = entry?;
        let source = entry.path();
        let destination = target.join(entry.file_name());
        if destination.exists() || !source.is_file() {
            continue;
        }
        fs::copy(source, destination)?;
    }
    Ok(())
}

#[cfg(not(windows))]
fn migrate_legacy_data_dir(_target: &FsPath) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn harden_path(path: &FsPath, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if path.exists() {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn harden_path(_path: &FsPath, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

fn config_value(db: &Connection, key: &str) -> Result<Option<Vec<u8>>, rusqlite::Error> {
    db.query_row(
        "SELECT value FROM app_config WHERE key = ?1",
        [key],
        |row| row.get(0),
    )
    .optional()
}

fn is_configured(db: &Connection) -> bool {
    config_value(db, "password_hash").ok().flatten().is_some()
}

fn hash_session_token(token: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().into()
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0_u8; N];
    rand::rng().fill(&mut bytes);
    bytes
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let mut key = [0_u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|error| error.to_string())?;
    Ok(key)
}

fn encrypt_secret(key: &[u8; 32], secret: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = random_bytes::<12>();
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), secret.as_bytes())
        .map_err(|_| "credential encryption failed".to_string())?;
    Ok((ciphertext, nonce.to_vec()))
}

fn decrypt_secret(key: &[u8; 32], ciphertext: &[u8], nonce: &[u8]) -> Result<String, String> {
    if nonce.len() != 12 {
        return Err("invalid credential nonce".to_string());
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| "credential decryption failed".to_string())?;
    String::from_utf8(plaintext).map_err(|_| "credential is not valid utf-8".to_string())
}

fn new_auth_token() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes::<32>())
}

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| {
            let (name, value) = part.trim().split_once('=')?;
            (name == "atimesh_session").then(|| value.to_string())
        })
}

fn authenticated(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(token) = cookie_token(headers) else {
        return false;
    };
    let Ok(mut sessions) = state.auth_sessions.lock() else {
        return false;
    };
    let Some(expires_at) = sessions.get(&token).copied() else {
        return false;
    };
    if expires_at <= SystemTime::now() {
        sessions.remove(&token);
        return false;
    }
    true
}

fn origin_allowed(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN) else {
        return true;
    };
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    origin == format!("http://{DEFAULT_HOST}:{}", state.app_port)
        || origin == format!("http://localhost:{}", state.app_port)
}

fn login_retry_after(state: &AppState) -> Option<u64> {
    let Ok(mut throttle) = state.login_throttle.lock() else {
        return Some(60);
    };
    let blocked_until = throttle.blocked_until?;
    if blocked_until <= SystemTime::now() {
        throttle.blocked_until = None;
        return None;
    }
    blocked_until
        .duration_since(SystemTime::now())
        .ok()
        .map(|duration| duration.as_secs().max(1))
}

fn record_login_failure(state: &AppState) {
    if let Ok(mut throttle) = state.login_throttle.lock() {
        throttle.failures = throttle.failures.saturating_add(1);
        let delay = 2_u64.saturating_pow(throttle.failures.min(6));
        throttle.blocked_until = Some(SystemTime::now() + Duration::from_secs(delay.min(60)));
    }
}

fn reset_login_throttle(state: &AppState) {
    if let Ok(mut throttle) = state.login_throttle.lock() {
        *throttle = LoginThrottle::default();
    }
}

fn valid_ssh_username(username: &str) -> bool {
    !username.is_empty()
        && username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn encode_uri_component(value: &str) -> String {
    value.bytes().fold(String::new(), |mut encoded, byte| {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
        encoded
    })
}

fn auth_error(status: StatusCode, message: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: message.to_string(),
        }),
    )
}

fn session_cookie(token: &str) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "atimesh_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800"
    ))
    .expect("valid session cookie")
}

fn load_servers(db: &Connection, key: &[u8; 32]) -> Result<HashMap<String, ServerConfig>, String> {
    let mut statement = db
        .prepare(
            "SELECT id, name, host, port, username, password_ciphertext, password_nonce, host_key FROM servers",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([], |row| {
            let id: String = row.get(0)?;
            let config = ServerConfig {
                name: row.get(1)?,
                host: row.get(2)?,
                port: row.get(3)?,
                username: row.get(4)?,
                password: decrypt_secret(
                    key,
                    &row.get::<_, Vec<u8>>(5)?,
                    &row.get::<_, Vec<u8>>(6)?,
                )
                .map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Blob,
                        Box::new(std::io::Error::other(error)),
                    )
                })?,
                host_key: row.get(7)?,
            };
            Ok((id, config))
        })
        .map_err(|error| error.to_string())?;
    rows.collect::<Result<HashMap<_, _>, _>>()
        .map_err(|error| error.to_string())
}

async fn list_servers(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ServerSummary>>, (StatusCode, String)> {
    if !authenticated(&state, &headers) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "authentication required".to_string(),
        ));
    }
    let servers = state
        .servers
        .lock()
        .map_err(|_| internal_error("server lock poisoned"))?;
    let summaries = servers
        .iter()
        .map(|(id, server)| ServerSummary {
            id: id.clone(),
            name: server.name.clone(),
            host: server.host.clone(),
            port: server.port,
            environment: "STAGING".to_string(),
            status: "healthy",
            latency: None,
            last_seen: "stored locally".to_string(),
            host_key: server.host_key.clone(),
        })
        .collect();
    Ok(Json(summaries))
}

async fn auth_status(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let configured = state
        .db
        .lock()
        .map(|db| is_configured(&db))
        .unwrap_or(false);
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(AuthStatusResponse {
            configured,
            authenticated: configured && authenticated(&state, &headers),
        }),
    )
        .into_response()
}

async fn auth_setup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AuthRequest>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    if !origin_allowed(&state, &headers) {
        return Err(auth_error(StatusCode::FORBIDDEN, "invalid request origin"));
    }
    if request.password.chars().count() < 8 {
        return Err(auth_error(
            StatusCode::BAD_REQUEST,
            "password must contain at least 8 characters",
        ));
    }
    let db = state
        .db
        .lock()
        .map_err(|_| auth_error(StatusCode::INTERNAL_SERVER_ERROR, "database lock poisoned"))?;
    if is_configured(&db) {
        return Err(auth_error(
            StatusCode::CONFLICT,
            "security password is already configured",
        ));
    }
    let password_salt = random_bytes::<16>();
    let encryption_salt = random_bytes::<16>();
    let salt_string = SaltString::encode_b64(&password_salt)
        .map_err(|_| auth_error(StatusCode::INTERNAL_SERVER_ERROR, "salt generation failed"))?;
    let password_hash = Argon2::default()
        .hash_password(request.password.as_bytes(), &salt_string)
        .map_err(|_| auth_error(StatusCode::INTERNAL_SERVER_ERROR, "password hashing failed"))?
        .to_string();
    db.execute(
        "INSERT INTO app_config(key, value) VALUES (?1, ?2)",
        params!["password_hash", password_hash.as_bytes()],
    )
    .map_err(|error| auth_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    db.execute(
        "INSERT INTO app_config(key, value) VALUES (?1, ?2)",
        params!["encryption_salt", encryption_salt.to_vec()],
    )
    .map_err(|error| auth_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let key = derive_key(&request.password, &encryption_salt)
        .map_err(|error| auth_error(StatusCode::INTERNAL_SERVER_ERROR, &error))?;
    *state
        .encryption_key
        .lock()
        .map_err(|_| auth_error(StatusCode::INTERNAL_SERVER_ERROR, "key lock poisoned"))? =
        Some(key);
    let token = new_auth_token();
    state
        .auth_sessions
        .lock()
        .map_err(|_| auth_error(StatusCode::INTERNAL_SERVER_ERROR, "session lock poisoned"))?
        .insert(
            token.clone(),
            SystemTime::now() + Duration::from_secs(8 * 60 * 60),
        );
    let mut response = Json(AuthStatusResponse {
        configured: true,
        authenticated: true,
    })
    .into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, session_cookie(&token));
    Ok(response)
}

async fn auth_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AuthRequest>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    if !origin_allowed(&state, &headers) {
        return Err(auth_error(StatusCode::FORBIDDEN, "invalid request origin"));
    }
    if let Some(retry_after) = login_retry_after(&state) {
        return Err(auth_error(
            StatusCode::TOO_MANY_REQUESTS,
            &format!("too many failed logins; retry in {retry_after} seconds"),
        ));
    }
    let db = state
        .db
        .lock()
        .map_err(|_| auth_error(StatusCode::INTERNAL_SERVER_ERROR, "database lock poisoned"))?;
    let Some(hash_bytes) = config_value(&db, "password_hash")
        .map_err(|error| auth_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?
    else {
        return Err(auth_error(
            StatusCode::PRECONDITION_FAILED,
            "security password is not configured",
        ));
    };
    let hash = String::from_utf8(hash_bytes)
        .map_err(|_| auth_error(StatusCode::INTERNAL_SERVER_ERROR, "invalid password hash"))?;
    let parsed = PasswordHash::new(&hash)
        .map_err(|_| auth_error(StatusCode::INTERNAL_SERVER_ERROR, "invalid password hash"))?;
    if Argon2::default()
        .verify_password(request.password.as_bytes(), &parsed)
        .is_err()
    {
        record_login_failure(&state);
        return Err(auth_error(
            StatusCode::UNAUTHORIZED,
            "invalid security password",
        ));
    }
    let salt = config_value(&db, "encryption_salt")
        .map_err(|error| auth_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?
        .ok_or_else(|| {
            auth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "encryption salt is missing",
            )
        })?;
    let key = derive_key(&request.password, &salt)
        .map_err(|error| auth_error(StatusCode::INTERNAL_SERVER_ERROR, &error))?;
    reset_login_throttle(&state);
    let servers = load_servers(&db, &key)
        .map_err(|error| auth_error(StatusCode::INTERNAL_SERVER_ERROR, &error))?;
    drop(db);
    *state
        .encryption_key
        .lock()
        .map_err(|_| auth_error(StatusCode::INTERNAL_SERVER_ERROR, "key lock poisoned"))? =
        Some(key);
    *state
        .servers
        .lock()
        .map_err(|_| auth_error(StatusCode::INTERNAL_SERVER_ERROR, "server lock poisoned"))? =
        servers;
    let token = new_auth_token();
    state
        .auth_sessions
        .lock()
        .map_err(|_| auth_error(StatusCode::INTERNAL_SERVER_ERROR, "session lock poisoned"))?
        .insert(
            token.clone(),
            SystemTime::now() + Duration::from_secs(8 * 60 * 60),
        );
    let mut response = Json(AuthStatusResponse {
        configured: true,
        authenticated: true,
    })
    .into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, session_cookie(&token));
    Ok(response)
}

async fn auth_logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<StatusCode, (StatusCode, String)> {
    if !origin_allowed(&state, &headers) {
        return Err((StatusCode::FORBIDDEN, "invalid request origin".to_string()));
    }
    if let Some(token) = cookie_token(&headers) {
        state
            .auth_sessions
            .lock()
            .map_err(|_| internal_error("session lock poisoned"))?
            .remove(&token);
    }
    *state
        .encryption_key
        .lock()
        .map_err(|_| internal_error("key lock poisoned"))? = None;
    state
        .servers
        .lock()
        .map_err(|_| internal_error("server lock poisoned"))?
        .clear();
    let expired = state
        .leases
        .lock()
        .map_err(|_| internal_error("lease lock poisoned"))?
        .drain()
        .map(|(_, lease)| lease.relay_task)
        .collect::<Vec<_>>();
    for relay_task in expired {
        relay_task.abort();
    }
    state
        .db
        .lock()
        .map_err(|_| internal_error("database lock poisoned"))?
        .execute("DELETE FROM ssh_sessions", [])
        .map_err(|error| internal_error(error.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

fn network_interface_preference(db: &Connection) -> Option<u32> {
    config_value(db, "network_interface_index")
        .ok()
        .flatten()
        .and_then(|value| String::from_utf8(value).ok())
        .and_then(|value| value.parse::<u32>().ok())
}

fn network_interface_summaries() -> Vec<NetworkInterfaceSummary> {
    let tunnel_markers = [
        "tun",
        "tap",
        "vpn",
        "virtual",
        "wsl",
        "docker",
        "clash",
        "meta",
        "tailscale",
        "zerotier",
        "wireguard",
        "wg",
        "utun",
    ];
    let mut grouped = std::collections::BTreeMap::<(Option<u32>, String), Vec<IpAddr>>::new();
    for interface in get_if_addrs().unwrap_or_default() {
        if interface.is_loopback() || interface.is_link_local() {
            continue;
        }
        let ip = interface.ip();
        grouped
            .entry((interface.index, interface.name))
            .or_default()
            .push(ip);
    }
    grouped
        .into_iter()
        .map(|((index, name), addresses)| {
            let is_tunnel = tunnel_markers
                .iter()
                .any(|marker| name.to_ascii_lowercase().contains(marker));
            let selectable = index.is_some() && !is_tunnel;
            NetworkInterfaceSummary {
                index,
                name,
                ip: addresses
                    .into_iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                is_tunnel,
                selectable,
            }
        })
        .collect()
}

async fn list_network_interfaces(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<NetworkInterfaceSummary>>, (StatusCode, String)> {
    if !authenticated(&state, &headers) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "authentication required".to_string(),
        ));
    }
    Ok(Json(network_interface_summaries()))
}

async fn get_network_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<NetworkSettingsResponse>, (StatusCode, String)> {
    if !origin_allowed(&state, &headers) {
        return Err((StatusCode::FORBIDDEN, "invalid request origin".to_string()));
    }
    if !authenticated(&state, &headers) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "authentication required".to_string(),
        ));
    }
    let interface_index = state
        .db
        .lock()
        .map_err(|_| internal_error("database lock poisoned"))
        .map(|db| network_interface_preference(&db))?;
    Ok(Json(NetworkSettingsResponse {
        interface_index,
        mode: if interface_index.is_some() {
            "manual"
        } else {
            "auto"
        },
    }))
}

async fn set_network_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<NetworkSettingsRequest>,
) -> Result<Json<NetworkSettingsResponse>, (StatusCode, String)> {
    if !origin_allowed(&state, &headers) {
        return Err((StatusCode::FORBIDDEN, "invalid request origin".to_string()));
    }
    if !authenticated(&state, &headers) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "authentication required".to_string(),
        ));
    }
    if let Some(index) = request.interface_index {
        let selected = network_interface_summaries()
            .into_iter()
            .any(|interface| interface.index == Some(index) && interface.selectable);
        if !selected {
            return Err((
                StatusCode::BAD_REQUEST,
                "the selected interface is unavailable or not a physical interface".to_string(),
            ));
        }
    }
    let db = state
        .db
        .lock()
        .map_err(|_| internal_error("database lock poisoned"))?;
    if let Some(index) = request.interface_index {
        db.execute(
            "INSERT INTO app_config(key, value) VALUES ('network_interface_index', ?1) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [index.to_string().as_bytes()],
        )
        .map_err(internal_error)?;
    } else {
        db.execute(
            "DELETE FROM app_config WHERE key = 'network_interface_index'",
            [],
        )
        .map_err(internal_error)?;
    }
    Ok(Json(NetworkSettingsResponse {
        interface_index: request.interface_index,
        mode: if request.interface_index.is_some() {
            "manual"
        } else {
            "auto"
        },
    }))
}

async fn create_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server_id): Path<String>,
) -> Result<Json<SessionResponse>, (StatusCode, String)> {
    if !origin_allowed(&state, &headers) {
        return Err((StatusCode::FORBIDDEN, "invalid request origin".to_string()));
    }
    if !authenticated(&state, &headers) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "authentication required".to_string(),
        ));
    }
    let target = state
        .servers
        .lock()
        .map_err(|_| internal_error("server lock poisoned"))?
        .get(&server_id)
        .cloned()
        .ok_or((
            StatusCode::PRECONDITION_FAILED,
            "server credentials are not configured".to_string(),
        ))?;
    if target.host_key.is_none() {
        return Err((
            StatusCode::PRECONDITION_FAILED,
            "host key verification required".to_string(),
        ));
    }
    let preferred_interface = state
        .db
        .lock()
        .map_err(|_| internal_error("database lock poisoned"))
        .map(|db| network_interface_preference(&db))?;
    // A fresh OS-owned listener is retained for the lifetime of this lease. This makes
    // every active server session unique and closes the bind race before SSH relay code runs.
    let listener = TcpListener::bind((DEFAULT_HOST, 0))
        .await
        .map_err(internal_error)?;
    let port = listener.local_addr().map_err(internal_error)?.port();
    let session_id = Uuid::new_v4().to_string();
    let token = Uuid::new_v4().simple().to_string();
    let relay_username = target.username.clone();
    let expires_at = SystemTime::now() + Duration::from_secs(10 * 60);
    let max_expires_at = SystemTime::now() + SESSION_MAX_DURATION;
    let relay_task = spawn_relay(listener, token.clone(), target, preferred_interface);
    let session = SessionLease {
        server_id: server_id.clone(),
        token: token.clone(),
        port,
        relay_task,
        expires_at,
        max_expires_at,
    };

    let mut leases = state
        .leases
        .lock()
        .map_err(|_| internal_error("lease lock poisoned"))?;
    // One active temporary link per server: generating again revokes and releases the old port.
    let old_session = leases
        .iter()
        .find(|(_, lease)| lease.server_id == server_id)
        .map(|(id, _)| id.clone());
    let db_result = state
        .db
        .lock()
        .map_err(|_| internal_error("database lock poisoned"))
        .and_then(|mut db| {
            let transaction = db
                .transaction()
                .map_err(|error| internal_error(error.to_string()))?;
            if let Some(old_session) = &old_session {
                transaction
                    .execute("DELETE FROM ssh_sessions WHERE id = ?1", [old_session])
                    .map_err(|error| internal_error(error.to_string()))?;
            }
            transaction
                .execute(
                    "INSERT INTO ssh_sessions(id, server_id, port, token_hash, expires_at, max_expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![session_id, server_id, port as i64, hash_session_token(&token).to_vec(), epoch_seconds(expires_at) as i64, epoch_seconds(max_expires_at) as i64],
                )
                .map_err(|error| internal_error(error.to_string()))?;
            transaction
                .commit()
                .map_err(|error| internal_error(error.to_string()))
        });
    if let Err(error) = db_result {
        session.relay_task.abort();
        return Err(error);
    }
    if let Some(old_session) = old_session {
        if let Some(old_lease) = leases.remove(&old_session) {
            old_lease.relay_task.abort();
        }
    }
    leases.insert(session_id.clone(), session);

    Ok(Json(SessionResponse {
        session_id,
        server_id,
        port,
        token: token.clone(),
        connect_command: format!(
            "ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no {}@{DEFAULT_HOST} -p {port}",
            relay_username.as_str()
        ),
        connect_uri: format!(
            "ssh://{}:{token}@{DEFAULT_HOST}:{port}",
            encode_uri_component(&relay_username)
        ),
        expires_at: epoch_seconds(expires_at),
        max_expires_at: epoch_seconds(max_expires_at),
    }))
}

async fn get_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server_id): Path<String>,
) -> Result<Json<SessionResponse>, (StatusCode, String)> {
    if !authenticated(&state, &headers) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "authentication required".to_string(),
        ));
    }

    let mut leases = state
        .leases
        .lock()
        .map_err(|_| internal_error("lease lock poisoned"))?;
    let session_id = leases
        .iter()
        .find(|(_, lease)| lease.server_id == server_id)
        .map(|(id, _)| id.clone())
        .ok_or((StatusCode::NOT_FOUND, "session not found".to_string()))?;

    if leases
        .get(&session_id)
        .map(|lease| lease.expires_at <= SystemTime::now())
        .unwrap_or(true)
    {
        state
            .db
            .lock()
            .map_err(|_| internal_error("database lock poisoned"))?
            .execute("DELETE FROM ssh_sessions WHERE id = ?1", [&session_id])
            .map_err(|error| internal_error(error.to_string()))?;
        if let Some(lease) = leases.remove(&session_id) {
            lease.relay_task.abort();
        }
        return Err((StatusCode::NOT_FOUND, "session not found".to_string()));
    }

    let lease = leases
        .get(&session_id)
        .ok_or((StatusCode::NOT_FOUND, "session not found".to_string()))?;
    let username = state
        .servers
        .lock()
        .map_err(|_| internal_error("server lock poisoned"))?
        .get(&server_id)
        .map(|server| server.username.clone())
        .ok_or((StatusCode::NOT_FOUND, "server not found".to_string()))?;

    Ok(Json(SessionResponse {
        session_id,
        server_id,
        port: lease.port,
        token: lease.token.clone(),
        connect_command: format!(
            "ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no {}@{DEFAULT_HOST} -p {}",
            username, lease.port
        ),
        connect_uri: format!(
            "ssh://{}:{}@{DEFAULT_HOST}:{}",
            encode_uri_component(&username),
            lease.token,
            lease.port
        ),
        expires_at: epoch_seconds(lease.expires_at),
        max_expires_at: epoch_seconds(lease.max_expires_at),
    }))
}

async fn upsert_server(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server_id): Path<String>,
    Json(server): Json<ServerConfig>,
) -> Result<StatusCode, (StatusCode, String)> {
    if !origin_allowed(&state, &headers) {
        return Err((StatusCode::FORBIDDEN, "invalid request origin".to_string()));
    }
    if !authenticated(&state, &headers) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "authentication required".to_string(),
        ));
    }
    if server.host.trim().is_empty()
        || server.username.trim().is_empty()
        || server.password.is_empty()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "host, username and password are required".to_string(),
        ));
    }
    if !valid_ssh_username(server.username.trim()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "username may contain only letters, digits, '.', '_' and '-'".to_string(),
        ));
    }
    if server.port == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "port must be between 1 and 65535".to_string(),
        ));
    }
    let existing_host_key = state
        .servers
        .lock()
        .map_err(|_| internal_error("server lock poisoned"))?
        .get(&server_id)
        .and_then(|existing| existing.host_key.clone());
    let preferred_interface = state
        .db
        .lock()
        .map_err(|_| internal_error("database lock poisoned"))
        .map(|db| network_interface_preference(&db))?;
    let scanned_host_key = scan_target_host_key(&server, preferred_interface)
        .await
        .map_err(|error| {
            (
                StatusCode::BAD_GATEWAY,
                format!("unable to verify target host key: {error}"),
            )
        })?;
    if let Some(existing_host_key) = existing_host_key {
        if existing_host_key != scanned_host_key {
            return Err((
                StatusCode::CONFLICT,
                "target host key changed; server was not saved".to_string(),
            ));
        }
    }
    let mut server = server;
    server.host_key = Some(scanned_host_key);
    let key = state
        .encryption_key
        .lock()
        .map_err(|_| internal_error("key lock poisoned"))?
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "authentication required".to_string(),
        ))?;
    let (ciphertext, nonce) = encrypt_secret(&key, &server.password).map_err(internal_error)?;
    state.db.lock().map_err(|_| internal_error("database lock poisoned"))?.execute(
        "INSERT INTO servers(id, name, host, port, username, password_ciphertext, password_nonce, host_key) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(id) DO UPDATE SET name=excluded.name, host=excluded.host, port=excluded.port, username=excluded.username, password_ciphertext=excluded.password_ciphertext, password_nonce=excluded.password_nonce, host_key=COALESCE(excluded.host_key, servers.host_key)",
        params![server_id, server.name, server.host, server.port as i64, server.username, ciphertext, nonce, server.host_key],
    ).map_err(internal_error)?;
    state
        .servers
        .lock()
        .map_err(|_| internal_error("server lock poisoned"))?
        .insert(server_id.clone(), server);
    revoke_server_leases(&state, &server_id)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_server(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server_id): Path<String>,
) -> Result<Json<ServerDetails>, (StatusCode, String)> {
    if !authenticated(&state, &headers) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "authentication required".to_string(),
        ));
    }
    let server = state
        .servers
        .lock()
        .map_err(|_| internal_error("server lock poisoned"))?
        .get(&server_id)
        .cloned()
        .ok_or((StatusCode::NOT_FOUND, "server not found".to_string()))?;
    Ok(Json(ServerDetails {
        id: server_id,
        name: server.name,
        host: server.host,
        port: server.port,
        username: server.username,
        environment: "STAGING".to_string(),
        host_key: server.host_key,
    }))
}

async fn update_server(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server_id): Path<String>,
    Json(request): Json<UpdateServerRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    if !origin_allowed(&state, &headers) {
        return Err((StatusCode::FORBIDDEN, "invalid request origin".to_string()));
    }
    if !authenticated(&state, &headers) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "authentication required".to_string(),
        ));
    }
    if request.name.trim().is_empty()
        || request.host.trim().is_empty()
        || request.username.trim().is_empty()
        || request.port == 0
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "name, host, username and valid port are required".to_string(),
        ));
    }
    if !valid_ssh_username(request.username.trim()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "username may contain only letters, digits, '.', '_' and '-'".to_string(),
        ));
    }
    let old = state
        .servers
        .lock()
        .map_err(|_| internal_error("server lock poisoned"))?
        .get(&server_id)
        .cloned()
        .ok_or((StatusCode::NOT_FOUND, "server not found".to_string()))?;
    let password = if request.password.is_empty() {
        old.password.clone()
    } else {
        request.password.clone()
    };
    let candidate = ServerConfig {
        name: request.name.trim().to_string(),
        host: request.host.trim().to_string(),
        port: request.port,
        username: request.username.trim().to_string(),
        password,
        host_key: old.host_key.clone(),
    };
    let preferred_interface = state
        .db
        .lock()
        .map_err(|_| internal_error("database lock poisoned"))
        .map(|db| network_interface_preference(&db))?;
    let scanned = scan_target_host_key(&candidate, preferred_interface)
        .await
        .map_err(|error| {
            (
                StatusCode::BAD_GATEWAY,
                format!("unable to verify target host key: {error}"),
            )
        })?;
    let key = state
        .encryption_key
        .lock()
        .map_err(|_| internal_error("key lock poisoned"))?
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "authentication required".to_string(),
        ))?;
    let (ciphertext, nonce) = encrypt_secret(&key, &candidate.password).map_err(internal_error)?;
    state.db.lock().map_err(|_| internal_error("database lock poisoned"))?.execute(
        "UPDATE servers SET name=?1, host=?2, port=?3, username=?4, password_ciphertext=?5, password_nonce=?6, host_key=?7 WHERE id=?8",
        params![candidate.name, candidate.host, candidate.port as i64, candidate.username, ciphertext, nonce, scanned, server_id],
    ).map_err(internal_error)?;
    state
        .servers
        .lock()
        .map_err(|_| internal_error("server lock poisoned"))?
        .insert(
            server_id.clone(),
            ServerConfig {
                host_key: Some(scanned),
                ..candidate
            },
        );
    revoke_server_leases(&state, &server_id)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn renew_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Result<Json<SessionStatusResponse>, (StatusCode, String)> {
    if !origin_allowed(&state, &headers) {
        return Err((StatusCode::FORBIDDEN, "invalid request origin".to_string()));
    }
    if !authenticated(&state, &headers) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "authentication required".to_string(),
        ));
    }
    let mut leases = state
        .leases
        .lock()
        .map_err(|_| internal_error("lease lock poisoned"))?;
    let (current_expires_at, max_expires_at) = leases
        .get_mut(&session_id)
        .map(|lease| (lease.expires_at, lease.max_expires_at))
        .ok_or((StatusCode::NOT_FOUND, "session not found".to_string()))?;
    if current_expires_at <= SystemTime::now() {
        return Err((StatusCode::GONE, "session expired".to_string()));
    }
    let next_expires_at = std::cmp::min(
        current_expires_at + Duration::from_secs(10 * 60),
        max_expires_at,
    );
    let updated = state
        .db
        .lock()
        .map_err(|_| internal_error("database lock poisoned"))?
        .execute(
            "UPDATE ssh_sessions SET expires_at = ?1 WHERE id = ?2",
            params![epoch_seconds(next_expires_at) as i64, session_id],
        )
        .map_err(|error| internal_error(error.to_string()))?;
    if updated != 1 {
        return Err(internal_error("session persistence record is missing"));
    }
    let lease = leases
        .get_mut(&session_id)
        .ok_or((StatusCode::NOT_FOUND, "session not found".to_string()))?;
    lease.expires_at = next_expires_at;
    Ok(Json(session_status_payload(&session_id, lease)))
}

async fn session_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Result<Json<SessionStatusResponse>, (StatusCode, String)> {
    if !authenticated(&state, &headers) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "authentication required".to_string(),
        ));
    }
    let mut leases = state
        .leases
        .lock()
        .map_err(|_| internal_error("lease lock poisoned"))?;
    let expired = leases
        .get(&session_id)
        .map(|lease| lease.expires_at <= SystemTime::now())
        .unwrap_or(false);
    if expired {
        state
            .db
            .lock()
            .map_err(|_| internal_error("database lock poisoned"))?
            .execute("DELETE FROM ssh_sessions WHERE id = ?1", [&session_id])
            .map_err(|error| internal_error(error.to_string()))?;
        if let Some(lease) = leases.remove(&session_id) {
            lease.relay_task.abort();
        }
        return Err((StatusCode::GONE, "session expired".to_string()));
    }
    let lease = leases
        .get(&session_id)
        .ok_or((StatusCode::NOT_FOUND, "session not found".to_string()))?;
    Ok(Json(session_status_payload(&session_id, lease)))
}

fn session_status_payload(session_id: &str, lease: &SessionLease) -> SessionStatusResponse {
    SessionStatusResponse {
        session_id: session_id.to_string(),
        server_id: lease.server_id.clone(),
        port: lease.port,
        expires_at: epoch_seconds(lease.expires_at),
        max_expires_at: epoch_seconds(lease.max_expires_at),
        status: "active",
    }
}

fn epoch_seconds(value: SystemTime) -> u64 {
    value
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn expire_sessions(
    leases: Arc<Mutex<HashMap<String, SessionLease>>>,
    db: Arc<Mutex<Connection>>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        interval.tick().await;
        let expired = {
            let mut guard = match leases.lock() {
                Ok(guard) => guard,
                Err(_) => continue,
            };
            let ids: Vec<String> = guard
                .iter()
                .filter(|(_, lease)| lease.expires_at <= SystemTime::now())
                .map(|(id, _)| id.clone())
                .collect();
            let mut tasks = Vec::new();
            for id in ids {
                if let Some(lease) = guard.remove(&id) {
                    tasks.push(lease.relay_task);
                    match db.lock() {
                        Ok(connection) => {
                            if let Err(error) =
                                connection.execute("DELETE FROM ssh_sessions WHERE id = ?1", [&id])
                            {
                                log_message(format!(
                                    "Unable to delete expired SSH session {id}: {error}"
                                ));
                            }
                        }
                        Err(_) => log_message(
                            "Unable to lock database while deleting expired SSH session",
                        ),
                    }
                }
            }
            tasks
        };
        for relay_task in expired {
            relay_task.abort();
        }
    }
}

async fn static_asset(uri: axum::http::Uri) -> Response {
    let requested = uri.path().trim_start_matches('/');
    let path = if requested.is_empty() {
        "index.html"
    } else {
        requested
    };
    if let Some(content) = FrontendAssets::get(path) {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        return (
            [(axum::http::header::CONTENT_TYPE, mime.as_ref())],
            content.data,
        )
            .into_response();
    }
    FrontendAssets::get("index.html")
        .map(|content| {
            (
                [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
                content.data,
            )
                .into_response()
        })
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response())
}

async fn revoke_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    if !origin_allowed(&state, &headers) {
        return Err((StatusCode::FORBIDDEN, "invalid request origin".to_string()));
    }
    if !authenticated(&state, &headers) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "authentication required".to_string(),
        ));
    }
    let mut leases = state
        .leases
        .lock()
        .map_err(|_| internal_error("lease lock poisoned"))?;
    if !leases.contains_key(&session_id) {
        Err((StatusCode::NOT_FOUND, "session not found".to_string()))
    } else {
        state
            .db
            .lock()
            .map_err(|_| internal_error("database lock poisoned"))?
            .execute("DELETE FROM ssh_sessions WHERE id = ?1", [&session_id])
            .map_err(|error| internal_error(error.to_string()))?;
        if let Some(lease) = leases.remove(&session_id) {
            lease.relay_task.abort();
        }
        Ok(StatusCode::NO_CONTENT)
    }
}

fn internal_error(error: impl ToString) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

fn revoke_server_leases(state: &AppState, server_id: &str) -> Result<(), (StatusCode, String)> {
    let mut leases = state
        .leases
        .lock()
        .map_err(|_| internal_error("lease lock poisoned"))?;
    let ids = leases
        .iter()
        .filter(|(_, lease)| lease.server_id == server_id)
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    if ids.is_empty() {
        return Ok(());
    }
    let db = state
        .db
        .lock()
        .map_err(|_| internal_error("database lock poisoned"))?;
    for id in &ids {
        db.execute("DELETE FROM ssh_sessions WHERE id = ?1", [id])
            .map_err(|error| internal_error(error.to_string()))?;
    }
    for id in ids {
        if let Some(lease) = leases.remove(&id) {
            lease.relay_task.abort();
        }
    }
    Ok(())
}

fn open_dashboard(url: &str) {
    if let Err(error) = webbrowser::open(url) {
        log_message(format!("Unable to open ATimeSsh dashboard: {error}"));
    }
}

fn run_tray(dashboard_url: String, shutdown_tx: oneshot::Sender<()>) -> ! {
    let event_loop = EventLoopBuilder::new().build();
    let menu = Menu::new();
    let open_item = MenuItem::new("打开管理后台 / Open dashboard", true, None);
    let exit_item = MenuItem::new("退出 / Exit", true, None);
    menu.append(&open_item).expect("unable to build tray menu");
    menu.append(&exit_item).expect("unable to build tray menu");
    let icon = Icon::from_rgba(tray_icon_rgba(), 32, 32).expect("unable to build tray icon");
    let _tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("ATimeSsh")
        .with_icon(icon)
        .build()
        .expect("unable to create system tray");
    let menu_receiver = MenuEvent::receiver();
    let shutdown_tx = Arc::new(Mutex::new(Some(shutdown_tx)));
    let open_id = open_item.id().clone();
    let exit_id = exit_item.id().clone();

    event_loop.run(move |_event, _window_target, control_flow| {
        *control_flow = ControlFlow::Wait;
        while let Ok(event) = menu_receiver.try_recv() {
            if event.id == open_id {
                open_dashboard(&dashboard_url);
            } else if event.id == exit_id {
                if let Ok(mut sender) = shutdown_tx.lock() {
                    if let Some(sender) = sender.take() {
                        let _ = sender.send(());
                    }
                }
                *control_flow = ControlFlow::Exit;
            }
        }
    });
}

fn tray_icon_rgba() -> Vec<u8> {
    let mut pixels = Vec::with_capacity(32 * 32 * 4);
    for y in 0i32..32 {
        for x in 0i32..32 {
            let edge = x < 3 || y < 3 || x >= 29 || y >= 29;
            let inside_a = (7..25).contains(&x)
                && (7..25).contains(&y)
                && (x - 16).abs() + (y - 16).abs() < 12;
            if edge {
                pixels.extend_from_slice(&[17, 22, 27, 0]);
            } else if inside_a {
                pixels.extend_from_slice(&[240, 188, 92, 255]);
            } else {
                pixels.extend_from_slice(&[17, 22, 27, 255]);
            }
        }
    }
    pixels
}

// Reserved for the relay accept loop. The listener is intentionally held in SessionLease
// until the SSH relay layer takes ownership of it.
#[allow(dead_code)]
async fn accept_relay(listener: TcpListener) -> Result<(), std::io::Error> {
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(proxy_placeholder(stream));
    }
}

async fn proxy_placeholder(mut stream: TcpStream) {
    use tokio::io::AsyncWriteExt;
    let _ = stream
        .write_all(b"ATimeSsh relay is waiting for SSH authentication.\r\n")
        .await;
}

#[derive(Clone)]
struct RelayServer {
    token: String,
    target: ServerConfig,
    preferred_interface: Option<u32>,
}

impl RusshServer for RelayServer {
    type Handler = RelayHandler;

    fn new_client(&mut self, _peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        RelayHandler {
            token: self.token.clone(),
            target: self.target.clone(),
            preferred_interface: self.preferred_interface,
            channels: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

struct TargetRequest {
    kind: TargetRequestKind,
    reply: oneshot::Sender<bool>,
}

enum TargetRequestKind {
    Pty {
        term: String,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: Vec<(Pty, u32)>,
    },
    Shell,
    Exec(Vec<u8>),
    Env {
        name: String,
        value: String,
    },
    Subsystem(String),
    WindowChange {
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    },
    Signal(Sig),
    Eof,
    Close,
}

struct RelayHandler {
    token: String,
    target: ServerConfig,
    preferred_interface: Option<u32>,
    channels: Arc<Mutex<HashMap<ChannelId, mpsc::Sender<TargetRequest>>>>,
}

#[derive(Clone)]
struct LocalSource {
    ip: IpAddr,
    interface_index: Option<u32>,
    #[allow(dead_code)]
    interface_name: String,
}

#[derive(Clone)]
struct TargetClient {
    expected_fingerprint: Option<String>,
    observed_fingerprint: Option<Arc<Mutex<Option<String>>>>,
}

impl client::Handler for TargetClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let fingerprint = server_public_key
            .public_key()
            .fingerprint(russh::keys::HashAlg::Sha256)
            .to_string();
        if let Some(observed) = &self.observed_fingerprint {
            if let Ok(mut value) = observed.lock() {
                *value = Some(fingerprint.clone());
            }
        }
        Ok(self
            .expected_fingerprint
            .as_deref()
            .map(|expected| expected == fingerprint)
            .unwrap_or(true))
    }
}

impl server::Handler for RelayHandler {
    type Error = russh::Error;

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self
            .send_target_request(channel, TargetRequestKind::Shell)
            .await
        {
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if user == self.target.username && password == self.token {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut target_session = connect_target(
            &self.target,
            TargetClient {
                expected_fingerprint: self.target.host_key.clone(),
                observed_fingerprint: None,
            },
            self.preferred_interface,
        )
        .await
        .map_err(|error| {
            log_message(format!("ATimeSsh target connection failed: {error}"));
            russh::Error::Disconnect
        })?;
        let auth = target_session
            .authenticate_password(&self.target.username, &self.target.password)
            .await
            .map_err(|_| russh::Error::Disconnect)?;
        if !auth.success() {
            return Err(russh::Error::Disconnect);
        }
        let target_channel = target_session
            .channel_open_session()
            .await
            .map_err(|_| russh::Error::Disconnect)?;
        let channel_id = channel.id();
        let (client_read, client_write) = channel.split();
        let (target_read, target_write) = target_channel.split();
        let (request_tx, request_rx) = mpsc::channel(32);
        self.channels
            .lock()
            .map_err(|_| russh::Error::Disconnect)?
            .insert(channel_id, request_tx);
        reply.accept().await;
        let channels = Arc::clone(&self.channels);
        tokio::spawn(async move {
            relay_session(
                client_read,
                client_write,
                target_read,
                target_write,
                request_rx,
                target_session,
            )
            .await;
            if let Ok(mut channels) = channels.lock() {
                channels.remove(&channel_id);
            }
        });
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let _ = self
            .send_target_request(channel, TargetRequestKind::Close)
            .await;
        if let Ok(mut channels) = self.channels.lock() {
            channels.remove(&channel);
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let _ = self
            .send_target_request(channel, TargetRequestKind::Eof)
            .await;
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.respond_to_target_request(
            channel,
            TargetRequestKind::Env {
                name: variable_name.to_string(),
                value: variable_value.to_string(),
            },
            session,
        )
        .await
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.respond_to_target_request(
            channel,
            TargetRequestKind::Subsystem(name.to_string()),
            session,
        )
        .await
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.respond_to_target_request(
            channel,
            TargetRequestKind::WindowChange {
                col_width,
                row_height,
                pix_width,
                pix_height,
            },
            session,
        )
        .await
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let _ = self
            .send_target_request(channel, TargetRequestKind::Signal(signal))
            .await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        command: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.respond_to_target_request(channel, TargetRequestKind::Exec(command.to_vec()), session)
            .await
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.respond_to_target_request(
            channel,
            TargetRequestKind::Pty {
                term: term.to_string(),
                col_width,
                row_height,
                pix_width,
                pix_height,
                modes: modes.to_vec(),
            },
            session,
        )
        .await
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        _data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Channel data is consumed by relay_session through ChannelReadHalf.
        Ok(())
    }
}

impl RelayHandler {
    async fn respond_to_target_request(
        &self,
        channel: ChannelId,
        kind: TargetRequestKind,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        if self.send_target_request(channel, kind).await {
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn send_target_request(&self, channel: ChannelId, kind: TargetRequestKind) -> bool {
        let (reply, response) = oneshot::channel();
        let request = TargetRequest { kind, reply };
        let sender = self
            .channels
            .lock()
            .ok()
            .and_then(|channels| channels.get(&channel).cloned());
        let Some(sender) = sender else { return false };
        if sender.send(request).await.is_err() {
            return false;
        }
        tokio::time::timeout(REQUEST_TIMEOUT, response)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(false)
    }
}

async fn relay_session(
    mut client_read: ChannelReadHalf,
    client_write: ChannelWriteHalf<Msg>,
    mut target_read: ChannelReadHalf,
    target_write: ChannelWriteHalf<client::Msg>,
    mut requests: mpsc::Receiver<TargetRequest>,
    target_session: client::Handle<TargetClient>,
) {
    loop {
        tokio::select! {
            request = requests.recv() => {
                let Some(request) = request else { break };
                let TargetRequest { kind, reply } = request;
                let result = match kind {
                    TargetRequestKind::Pty { term, col_width, row_height, pix_width, pix_height, modes } => target_write.request_pty(true, &term, col_width, row_height, pix_width, pix_height, &modes).await,
                    TargetRequestKind::Shell => target_write.request_shell(true).await,
                    TargetRequestKind::Exec(command) => target_write.exec(true, command).await,
                    TargetRequestKind::Env { name, value } => target_write.set_env(true, name, value).await,
                    TargetRequestKind::Subsystem(name) => target_write.request_subsystem(true, name).await,
                    TargetRequestKind::WindowChange { col_width, row_height, pix_width, pix_height } => target_write.window_change(col_width, row_height, pix_width, pix_height).await,
                    TargetRequestKind::Signal(signal) => target_write.signal(signal).await,
                    TargetRequestKind::Eof => target_write.eof().await,
                    TargetRequestKind::Close => target_write.close().await,
                };
                let success = result.is_ok();
                let _ = reply.send(success);
                if result.is_err() {
                    break;
                }
            }
            message = client_read.wait() => {
                match message {
                    Some(ChannelMsg::Data { data }) => {
                        if target_write.data_bytes(data).await.is_err() { break; }
                    }
                    Some(ChannelMsg::ExtendedData { data, ext }) => {
                        if target_write.extended_data_bytes(ext, data).await.is_err() { break; }
                    }
                    Some(ChannelMsg::Eof) => {
                        let _ = target_write.eof().await;
                    }
                    Some(ChannelMsg::Close) | None => {
                        let _ = target_write.close().await;
                        break;
                    }
                    _ => {}
                }
            }
            message = target_read.wait() => {
                match message {
                    Some(ChannelMsg::Data { data }) => {
                        if client_write.data_bytes(data).await.is_err() { break; }
                    }
                    Some(ChannelMsg::ExtendedData { data, ext }) => {
                        if client_write.extended_data_bytes(ext, data).await.is_err() { break; }
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        let _ = client_write.exit_status(exit_status).await;
                    }
                    Some(ChannelMsg::Eof) => {
                        let _ = client_write.eof().await;
                    }
                    Some(ChannelMsg::Close) | None => {
                        let _ = client_write.close().await;
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    let _ = target_session
        .disconnect(russh::Disconnect::ByApplication, "relay closed", "en")
        .await;
}

fn local_source_candidates(preferred_interface: Option<u32>) -> Vec<LocalSource> {
    let tunnel_markers = [
        "tun",
        "tap",
        "vpn",
        "virtual",
        "wsl",
        "docker",
        "clash",
        "meta",
        "tailscale",
        "zerotier",
        "wireguard",
        "wg",
        "utun",
    ];
    let mut candidates = get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|interface| {
            let ip = interface.ip();
            if interface.is_loopback() || interface.is_link_local() {
                return None;
            }
            let name = interface.name.to_ascii_lowercase();
            let is_tunnel = tunnel_markers.iter().any(|marker| name.contains(marker));
            if let Some(preferred_index) = preferred_interface {
                if interface.index != Some(preferred_index) {
                    return None;
                }
            }
            Some((
                is_tunnel,
                LocalSource {
                    ip,
                    interface_index: interface.index,
                    interface_name: interface.name,
                },
            ))
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|(is_tunnel, source)| (*is_tunnel, source.ip.to_string()));
    candidates.dedup_by(|left, right| left.1.ip == right.1.ip);
    candidates.into_iter().map(|(_, source)| source).collect()
}

#[cfg(windows)]
fn force_socket_interface(
    socket: &TcpSocket,
    source: LocalSource,
    remote: IpAddr,
) -> Result<(), String> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        setsockopt, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, IP_UNICAST_IF, SOCKET_ERROR,
    };

    let Some(interface_index) = source.interface_index else {
        return Ok(());
    };
    let option = interface_index.to_be_bytes();
    let (level, name) = match remote {
        IpAddr::V4(_) => (IPPROTO_IP, IP_UNICAST_IF),
        IpAddr::V6(_) => (IPPROTO_IPV6, IPV6_UNICAST_IF),
    };
    let result = unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            level,
            name,
            option.as_ptr(),
            option.len() as i32,
        )
    };
    if result == SOCKET_ERROR {
        return Err(format!(
            "设置物理网卡接口 {} 失败：{}",
            interface_index,
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn force_socket_interface(
    socket: &TcpSocket,
    source: LocalSource,
    _remote: IpAddr,
) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    let mut device = source.interface_name.into_bytes();
    device.push(0);
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            device.as_ptr().cast(),
            device.len() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(format!(
            "绑定 Linux 网卡 {} 失败：{}",
            source.interface_name,
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn force_socket_interface(
    socket: &TcpSocket,
    source: LocalSource,
    remote: IpAddr,
) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    let index = source
        .interface_index
        .ok_or_else(|| "macOS 网卡缺少接口索引".to_string())?;
    let (level, option) = match remote {
        IpAddr::V4(_) => (libc::IPPROTO_IP, libc::IP_BOUND_IF),
        IpAddr::V6(_) => (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF),
    };
    let value = index as libc::c_uint;
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            (&value as *const libc::c_uint).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(format!(
            "绑定 macOS 网卡 {} 失败：{}",
            source.interface_name,
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
fn force_socket_interface(
    _socket: &TcpSocket,
    _source: LocalSource,
    _remote: IpAddr,
) -> Result<(), String> {
    Err("当前平台不支持严格的物理网卡绑定".to_string())
}

async fn connect_target(
    target: &ServerConfig,
    handler: TargetClient,
    preferred_interface: Option<u32>,
) -> Result<client::Handle<TargetClient>, String> {
    let remote_addresses = lookup_host((target.host.as_str(), target.port))
        .await
        .map_err(|error| format!("解析目标地址失败：{error}"))?
        .collect::<Vec<_>>();
    if remote_addresses.is_empty() {
        return Err("目标地址没有可用的 IP".to_string());
    }
    let config = Arc::new(client::Config {
        inactivity_timeout: None,
        ..Default::default()
    });
    let sources = local_source_candidates(preferred_interface);
    let mut attempts = 0_u32;
    let mut last_error = String::new();
    for remote in &remote_addresses {
        for source in &sources {
            if matches!(
                (source.ip, remote.ip()),
                (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_))
            ) {
                continue;
            }
            attempts += 1;
            let socket = match source.ip {
                IpAddr::V4(_) => TcpSocket::new_v4(),
                IpAddr::V6(_) => TcpSocket::new_v6(),
            }
            .map_err(|error| format!("创建本地连接失败：{error}"))?;
            socket
                .bind(SocketAddr::new(source.ip, 0))
                .map_err(|error| format!("绑定本地网卡 {} 失败：{error}", source.ip))?;
            if force_socket_interface(&socket, source.clone(), remote.ip()).is_err() {
                continue;
            }
            if let Ok(Ok(stream)) =
                tokio::time::timeout(Duration::from_secs(8), socket.connect(*remote)).await
            {
                if let Ok(Ok(session)) = tokio::time::timeout(
                    Duration::from_secs(8),
                    client::connect_stream(config.clone(), stream, handler.clone()),
                )
                .await
                {
                    return Ok(session);
                }
            }
        }
        if preferred_interface.is_some() {
            continue;
        }
        attempts += 1;
        match tokio::time::timeout(Duration::from_secs(8), TcpStream::connect(*remote)).await {
            Ok(Ok(stream)) => match tokio::time::timeout(
                Duration::from_secs(8),
                client::connect_stream(config.clone(), stream, handler.clone()),
            )
            .await
            {
                Ok(Ok(session)) => return Ok(session),
                Ok(Err(error)) => last_error = format!("SSH 握手失败：{error}"),
                Err(_) => last_error = "SSH 握手超时（8 秒）".to_string(),
            },
            Ok(Err(error)) => last_error = format!("默认路由连接失败：{error}"),
            Err(_) => last_error = "默认路由连接超时（8 秒）".to_string(),
        }
    }
    Err(format!(
        "SSH 连接失败：已尝试绕过 TUN 的物理网卡和默认路由（{attempts} 次），最后错误：{last_error}"
    ))
}

async fn scan_target_host_key(
    target: &ServerConfig,
    preferred_interface: Option<u32>,
) -> Result<String, String> {
    let observed = Arc::new(Mutex::new(None));
    let mut session = connect_target(
        target,
        TargetClient {
            expected_fingerprint: None,
            observed_fingerprint: Some(observed.clone()),
        },
        preferred_interface,
    )
    .await?;
    let auth = session
        .authenticate_password(&target.username, &target.password)
        .await
        .map_err(|error| format!("SSH 认证请求失败：{error}"))?;
    if !auth.success() {
        return Err("SSH 用户名或密码验证失败".to_string());
    }
    let _ = session
        .disconnect(
            russh::Disconnect::ByApplication,
            "host key scan complete",
            "en",
        )
        .await;
    observed
        .lock()
        .ok()
        .and_then(|value| value.clone())
        .ok_or_else(|| "SSH 握手未返回主机指纹".to_string())
}

fn spawn_relay(
    listener: TcpListener,
    token: String,
    target: ServerConfig,
    preferred_interface: Option<u32>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let config = russh::server::Config {
            auth_rejection_time: std::time::Duration::from_millis(250),
            auth_rejection_time_initial: Some(std::time::Duration::from_millis(0)),
            inactivity_timeout: None,
            keys: vec![russh::keys::PrivateKey::random(
                &mut rand::rng(),
                russh::keys::Algorithm::Ed25519,
            )
            .expect("unable to create relay host key")],
            preferred: Preferred::default(),
            ..Default::default()
        };
        let config = Arc::new(config);
        let mut server = RelayServer {
            token,
            target,
            preferred_interface,
        };
        let running = server.run_on_socket(config, &listener);
        if let Err(error) = running.await {
            log_message(format!("ATimeSsh relay stopped: {error}"));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_component_is_percent_encoded() {
        assert_eq!(encode_uri_component("alice@example"), "alice%40example");
        assert_eq!(encode_uri_component("safe-user_1"), "safe-user_1");
    }

    #[test]
    fn ssh_usernames_are_restricted_to_shell_safe_characters() {
        assert!(valid_ssh_username("deploy_user-1"));
        assert!(!valid_ssh_username("alice@example"));
        assert!(!valid_ssh_username("deploy user"));
        assert!(!valid_ssh_username(""));
    }

    #[test]
    fn login_throttle_blocks_then_resets() {
        let state = AppState {
            app_port: 1,
            leases: Arc::new(Mutex::new(HashMap::new())),
            servers: Arc::new(Mutex::new(HashMap::new())),
            db: Arc::new(Mutex::new(
                Connection::open_in_memory().expect("open test db"),
            )),
            auth_sessions: Arc::new(Mutex::new(HashMap::new())),
            encryption_key: Arc::new(Mutex::new(None)),
            login_throttle: Arc::new(Mutex::new(LoginThrottle::default())),
        };
        assert!(login_retry_after(&state).is_none());
        record_login_failure(&state);
        assert!(login_retry_after(&state).is_some());
        reset_login_throttle(&state);
        assert!(login_retry_after(&state).is_none());
    }

    #[test]
    fn credentials_round_trip_with_authenticated_encryption() {
        let key = [7_u8; 32];
        let (ciphertext, nonce) = encrypt_secret(&key, "secret-value").expect("encrypt");
        assert_eq!(
            decrypt_secret(&key, &ciphertext, &nonce).expect("decrypt"),
            "secret-value"
        );
        assert!(decrypt_secret(&[8_u8; 32], &ciphertext, &nonce).is_err());
    }

    #[derive(Clone)]
    struct FakeTarget;

    impl russh::server::Server for FakeTarget {
        type Handler = Self;

        fn new_client(&mut self, _peer_addr: Option<SocketAddr>) -> Self::Handler {
            self.clone()
        }
    }

    impl russh::server::Handler for FakeTarget {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            _user: &str,
            _password: &str,
        ) -> Result<russh::server::Auth, Self::Error> {
            Ok(russh::server::Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            _channel: Channel<Msg>,
            reply: russh::server::ChannelOpenHandle,
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn exec_request(
            &mut self,
            channel: ChannelId,
            _command: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            session.channel_success(channel)?;
            session.data(channel, b"stdout".to_vec())?;
            session.extended_data(channel, 1, b"stderr".to_vec())?;
            session.eof(channel)?;
            session.exit_status_request(channel, 23)?;
            session.close(channel)?;
            Ok(())
        }
    }

    #[derive(Clone)]
    struct AcceptAnyKey;

    impl client::Handler for AcceptAnyKey {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            _server_public_key: &russh::keys::PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    #[tokio::test]
    async fn relay_preserves_exit_status_after_target_eof() {
        let target_listener = TcpListener::bind((DEFAULT_HOST, 0))
            .await
            .expect("target listener");
        let target_addr = target_listener.local_addr().expect("target address");
        let target_config = Arc::new(russh::server::Config {
            inactivity_timeout: None,
            keys: vec![russh::keys::PrivateKey::random(
                &mut rand::rng(),
                russh::keys::Algorithm::Ed25519,
            )
            .expect("target key")],
            ..Default::default()
        });
        let target_task = tokio::spawn(async move {
            let (stream, _) = target_listener.accept().await.expect("target connection");
            russh::server::run_stream(target_config, stream, FakeTarget)
                .await
                .expect("target server");
        });

        let relay_listener = TcpListener::bind((DEFAULT_HOST, 0))
            .await
            .expect("relay listener");
        let relay_addr = relay_listener.local_addr().expect("relay address");
        let target = ServerConfig {
            name: "fake".to_string(),
            host: DEFAULT_HOST.to_string(),
            port: target_addr.port(),
            username: "target-user".to_string(),
            password: "target-password".to_string(),
            host_key: None,
        };
        let relay_task = spawn_relay(relay_listener, "relay-token".to_string(), target, None);
        let client_config = Arc::new(client::Config {
            inactivity_timeout: None,
            ..Default::default()
        });
        let mut client = client::connect(client_config, relay_addr, AcceptAnyKey)
            .await
            .expect("relay connection");
        assert!(client
            .authenticate_password("target-user", "relay-token")
            .await
            .expect("relay auth")
            .success());
        let mut channel = client.channel_open_session().await.expect("relay channel");
        channel.exec(true, "test").await.expect("exec request");

        let mut saw_eof = false;
        let mut saw_exit_status = false;
        let mut saw_close = false;
        while let Some(message) = tokio::time::timeout(Duration::from_secs(5), channel.wait())
            .await
            .expect("relay response timeout")
        {
            match message {
                ChannelMsg::Eof => saw_eof = true,
                ChannelMsg::ExitStatus { exit_status } => {
                    assert_eq!(exit_status, 23);
                    assert!(saw_eof, "exit-status was lost or reordered before EOF");
                    saw_exit_status = true;
                }
                ChannelMsg::Close => {
                    saw_close = true;
                    break;
                }
                _ => {}
            }
        }
        assert!(saw_eof);
        assert!(saw_exit_status);
        assert!(saw_close);
        let _ = client
            .disconnect(russh::Disconnect::ByApplication, "test complete", "en")
            .await;
        relay_task.abort();
        target_task.abort();
    }

    #[cfg(unix)]
    #[test]
    fn private_permissions_are_applied() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("atimesh-permissions-{}", Uuid::new_v4()));
        fs::create_dir(&path).expect("create test directory");
        harden_path(&path, 0o700).expect("harden test directory");
        assert_eq!(
            fs::metadata(&path)
                .expect("stat test directory")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        fs::remove_dir(&path).expect("remove test directory");
    }
}
